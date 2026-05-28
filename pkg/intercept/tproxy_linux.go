// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

//go:build linux

package intercept

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// soOriginalDst is the linux-specific getsockopt name for retrieving
// the original destination of a connection that was REDIRECTed by
// iptables/nftables. Defined in <linux/netfilter_ipv4.h>.
const soOriginalDst = 80

type tproxyInterceptor struct {
	ln     net.Listener
	alloc  *VIPAllocator
	logger *slog.Logger

	accepts   chan *InterceptedConn
	closeOnce sync.Once
	closed    chan struct{}
}

// NewTProxy listens on listenAddr and emits InterceptedConn for each
// REDIRECTed conn. The original destination IP is reverse-looked up in
// alloc to find the service name.
//
// Iptables setup (caller's responsibility, typically a deploy/k8s init
// container):
//
//	iptables -t nat -A OUTPUT \
//	    -p tcp -d 100.64.0.0/10 \
//	    -j REDIRECT --to-port <port>
func NewTProxy(listenAddr string, alloc *VIPAllocator, logger *slog.Logger) (Interceptor, error) {
	if alloc == nil {
		return nil, errors.New("intercept: nil VIPAllocator")
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		logger.Warn("intercept: tproxy listen failed", "addr", listenAddr, "err", err)
		return nil, fmt.Errorf("intercept: tproxy listen: %w", err)
	}
	logger.Info("intercept: tproxy listener bound", "addr", ln.Addr().String())
	t := &tproxyInterceptor{
		ln:      ln,
		alloc:   alloc,
		logger:  logger,
		accepts: make(chan *InterceptedConn),
		closed:  make(chan struct{}),
	}
	go t.acceptLoop()
	return t, nil
}

func (t *tproxyInterceptor) acceptLoop() {
	for {
		c, err := t.ln.Accept()
		if err != nil {
			select {
			case <-t.closed:
				return
			default:
			}
			t.logger.Warn("intercept: tproxy accept failed", "err", err)
			return
		}
		tc, ok := c.(*net.TCPConn)
		if !ok {
			t.logger.Warn("intercept: tproxy non-TCP conn dropped",
				"peer", c.RemoteAddr().String())
			_ = c.Close()
			continue
		}
		dst, err := origDst4(tc)
		if err != nil {
			t.logger.Warn("intercept: SO_ORIGINAL_DST failed",
				"peer", c.RemoteAddr().String(), "err", err)
			_ = c.Close()
			continue
		}
		svc := t.alloc.Lookup(dst.Addr())
		if svc == "" {
			t.logger.Warn("intercept: VIP lookup miss",
				"peer", c.RemoteAddr().String(), "dst", dst.String())
			_ = c.Close()
			continue
		}
		t.logger.Debug("intercept: tproxy accepted",
			"peer", c.RemoteAddr().String(), "dst", dst.String(), "svc", svc)
		select {
		case t.accepts <- &InterceptedConn{
			Local:     c,
			OrigDest:  &net.TCPAddr{IP: dst.Addr().AsSlice(), Port: int(dst.Port())},
			TargetSvc: svc,
		}:
		case <-t.closed:
			_ = c.Close()
			return
		}
	}
}

func (t *tproxyInterceptor) Accept(ctx context.Context) (*InterceptedConn, error) {
	select {
	case ic := <-t.accepts:
		return ic, nil
	case <-t.closed:
		return nil, ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (t *tproxyInterceptor) Close() error {
	t.closeOnce.Do(func() {
		close(t.closed)
		_ = t.ln.Close()
	})
	return nil
}

// origDst4 retrieves SO_ORIGINAL_DST on a redirected IPv4 socket.
//
// The returned bytes are a struct sockaddr_in:
//
//	bytes 0-1:  sin_family (AF_INET = 2)
//	bytes 2-3:  sin_port    (network order)
//	bytes 4-7:  sin_addr    (network order)
//	bytes 8-15: padding
func origDst4(c *net.TCPConn) (netip.AddrPort, error) {
	sc, err := c.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	var raw [16]byte
	size := uint32(len(raw))
	var inErr error
	// unsafe.Pointer is the standard pattern for Linux syscall args
	// (see x/sys/unix examples); the values point at stack-locals
	// kept alive for the duration of the call.
	cerr := sc.Control(func(fd uintptr) {
		_, _, e := unix.Syscall6(
			unix.SYS_GETSOCKOPT,
			fd,
			unix.IPPROTO_IP,
			soOriginalDst,
			uintptr(unsafe.Pointer(&raw[0])), // #nosec G103
			uintptr(unsafe.Pointer(&size)),   // #nosec G103
			0,
		)
		if e != 0 {
			inErr = e
		}
	})
	if cerr != nil {
		return netip.AddrPort{}, cerr
	}
	if inErr != nil {
		return netip.AddrPort{}, inErr
	}
	port := binary.BigEndian.Uint16(raw[2:4])
	addr := netip.AddrFrom4([4]byte{raw[4], raw[5], raw[6], raw[7]})
	return netip.AddrPortFrom(addr, port), nil
}
