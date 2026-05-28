// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package intercept

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// DNSServer answers A queries for service names by mapping them through
// a VIPAllocator. It serves on UDP only — the resolver paths we care
// about (musl's getaddrinfo, glibc, K8s sidecar resolv.conf) all use
// UDP for short answers.
//
// Names recognized:
// - bare service name: "svc-payments"
// - with the configured suffix: "svc-payments.outrelay"
// - case-insensitive
//
// Anything else returns NXDOMAIN.
type DNSServer struct {
	listenAddr string
	suffix     string // dot-prefixed, e.g. ".outrelay" — empty means no suffix
	alloc      *VIPAllocator
	logger     *slog.Logger

	mu sync.Mutex
	pc net.PacketConn
}

// NewDNSServer constructs (but does not start) a DNS server. A nil
// logger disables logging.
func NewDNSServer(listenAddr, suffix string, alloc *VIPAllocator, logger *slog.Logger) (*DNSServer, error) {
	if alloc == nil {
		return nil, errors.New("intercept: nil VIPAllocator")
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	suffix = strings.ToLower(strings.TrimSpace(suffix))
	if suffix != "" && !strings.HasPrefix(suffix, ".") {
		suffix = "." + suffix
	}
	return &DNSServer{
		listenAddr: listenAddr,
		suffix:     suffix,
		alloc:      alloc,
		logger:     logger,
	}, nil
}

// Addr returns the bound address. Useful when listenAddr was ":0" so
// the test gets an ephemeral port.
func (s *DNSServer) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pc == nil {
		return nil
	}
	return s.pc.LocalAddr()
}

// Run binds and serves until ctx is canceled.
func (s *DNSServer) Run(ctx context.Context) error {
	pc, err := net.ListenPacket("udp", s.listenAddr)
	if err != nil {
		s.logger.Warn("intercept: dns listen failed",
			"addr", s.listenAddr, "err", err)
		return fmt.Errorf("intercept: dns listen: %w", err)
	}
	s.mu.Lock()
	s.pc = pc
	s.mu.Unlock()
	s.logger.Info("intercept: dns server running",
		"addr", pc.LocalAddr().String(), "suffix", s.suffix)

	go func() {
		<-ctx.Done()
		_ = pc.Close()
	}()

	buf := make([]byte, 1500)
	for {
		_ = pc.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			var nerr net.Error
			if errors.As(err, &nerr) && nerr.Timeout() {
				continue
			}
			return err
		}
		resp, ok := s.respond(buf[:n])
		if !ok {
			continue
		}
		_, _ = pc.WriteTo(resp, addr)
	}
}

// respond builds an answer for one DNS message. ok=false means the
// message was malformed and should be silently dropped.
func (s *DNSServer) respond(query []byte) ([]byte, bool) {
	var p dnsmessage.Parser
	hdr, err := p.Start(query)
	if err != nil {
		return nil, false
	}
	q, err := p.Question()
	if err != nil {
		return nil, false
	}

	answer := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               hdr.ID,
			Response:         true,
			RecursionDesired: hdr.RecursionDesired,
		},
		Questions: []dnsmessage.Question{q},
	}

	switch q.Type {
	case dnsmessage.TypeA:
		if vip, ok := s.lookup(q.Name.String()); ok {
			b := vip.As4()
			answer.Answers = []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{
					Name:  q.Name,
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					TTL:   60,
				},
				Body: &dnsmessage.AResource{A: b},
			}}
			s.logger.Debug("intercept: dns A answer",
				"name", q.Name.String(), "vip", vip.String())
		} else {
			s.logger.Debug("intercept: dns A nxdomain",
				"name", q.Name.String())
			answer.RCode = dnsmessage.RCodeNameError
		}
	case dnsmessage.TypeAAAA:
		// We don't issue v6 VIPs.
		s.logger.Debug("intercept: dns AAAA nxdomain (v4 only)",
			"name", q.Name.String())
		answer.RCode = dnsmessage.RCodeNameError
	default:
		s.logger.Debug("intercept: dns unsupported qtype",
			"name", q.Name.String(), "type", q.Type.String())
		answer.RCode = dnsmessage.RCodeNotImplemented
	}

	out, err := answer.Pack()
	if err != nil {
		return nil, false
	}
	return out, true
}

// lookup strips the configured suffix and trailing dot, then asks the
// allocator (read-only). The agent must have called alloc.Allocate for
// every consumed service at startup; queries for unknown names get
// NXDOMAIN.
func (s *DNSServer) lookup(qname string) (netip.Addr, bool) {
	name := strings.ToLower(strings.TrimSuffix(qname, "."))
	if s.suffix != "" {
		if !strings.HasSuffix(name, s.suffix) {
			return netip.Addr{}, false
		}
		name = strings.TrimSuffix(name, s.suffix)
	}
	if name == "" {
		return netip.Addr{}, false
	}
	return s.alloc.LookupName(name)
}
