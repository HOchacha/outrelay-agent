// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

// Package candidate gathers the agent's possible reachable
// addresses for P2P promotion. Two kinds are produced:
//
//   - host:  every non-loopback / non-link-local IP on a local
//     interface, paired with the agent's negotiated session port.
//   - srflx: the relay's observed src ip:port for this agent's QUIC
//     connection (server-reflexive, RFC 8445 terminology).
//
// The agent's session uses these to populate a CandidateOffer that
// flows to the peer agent through the relay.
package candidate

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/boanlab/OutRelay/lib/orp"
	orpv1 "github.com/boanlab/OutRelay/lib/orp/v1"
	"github.com/boanlab/OutRelay/lib/transport"
)

// Candidate is the address-and-priority pair carried in
// CandidateOffer / CandidateAnswer.
type Candidate struct {
	Kind     string // "host" | "srflx"
	Addr     netip.AddrPort
	Priority uint32
}

// String renders a candidate for logs.
func (c Candidate) String() string {
	return fmt.Sprintf("%s://%s prio=%d", c.Kind, c.Addr.String(), c.Priority)
}

// HostCandidates returns one Candidate per usable local interface
// address, paired with port. Loopback (127.0.0.0/8, ::1), link-local,
// and multicast addresses are dropped — they aren't routable beyond
// the host. The list is intentionally small.
func HostCandidates(port uint16) []Candidate {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []Candidate
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP == nil {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipnet.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if !ip.IsValid() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
			continue
		}
		out = append(out, Candidate{
			Kind:     "host",
			Addr:     netip.AddrPortFrom(ip, port),
			Priority: hostPriority(ip),
		})
	}
	return out
}

// hostPriority follows the simplified RFC 8445 ranking: prefer
// global > private > everything else, IPv6 over IPv4 within each
// class. Returned values land in [0, 100].
func hostPriority(ip netip.Addr) uint32 {
	base := uint32(50)
	if ip.IsPrivate() {
		base = 30
	}
	if ip.IsGlobalUnicast() && !ip.IsPrivate() {
		base = 70
	}
	if ip.Is6() {
		base += 10
	}
	return base
}

// srflxPort generator — request_id sequencing for OBSERVED_ADDR_QUERY.
var nextRequestID atomic.Uint64

// QueryServerReflexive sends an OBSERVED_ADDR_QUERY on ctrl and waits
// for the matching OBSERVED_ADDR_RESP. The returned Candidate has
// kind="srflx" and Priority below the host candidates so direct
// links are tried first.
//
// timeout bounds the round-trip; the relay always responds quickly
// (it just echoes RemoteAddr) so a short window suffices.
func QueryServerReflexive(ctx context.Context, ctrl transport.Stream, timeout time.Duration) (Candidate, error) {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	id := nextRequestID.Add(1)
	if id == 0 {
		// request_id is a correlation token, not a secret — math/rand
		// is sufficient and crypto/rand would needlessly block.
		id = uint64(rand.Uint32()) | 1 // #nosec G404
	}
	if err := orp.WriteFrame(ctrl, orp.FrameTypeObservedAddrQuery, &orpv1.ObservedAddrQuery{
		RequestId: id,
	}); err != nil {
		return Candidate{}, fmt.Errorf("candidate: send query: %w", err)
	}

	type result struct {
		c   Candidate
		err error
	}
	done := make(chan result, 1)
	go func() {
		f, err := orp.ParseFrame(ctrl)
		if err != nil {
			done <- result{err: fmt.Errorf("candidate: read response: %w", err)}
			return
		}
		if f.Type != orp.FrameTypeObservedAddrResp {
			done <- result{err: fmt.Errorf("candidate: unexpected frame %v", f.Type)}
			return
		}
		r := &orpv1.ObservedAddrResp{}
		if err := orp.UnmarshalProto(f, orp.FrameTypeObservedAddrResp, r); err != nil {
			done <- result{err: err}
			return
		}
		if r.RequestId != id {
			done <- result{err: errors.New("candidate: response id mismatch")}
			return
		}
		ip, err := netip.ParseAddr(r.Ip)
		if err != nil {
			done <- result{err: fmt.Errorf("candidate: parse ip %q: %w", r.Ip, err)}
			return
		}
		done <- result{c: Candidate{
			Kind: "srflx",
			// proto carries port as uint32 (no uint16 in proto3); a
			// real TCP/UDP port never exceeds 65535.
			Addr:     netip.AddrPortFrom(ip, uint16(r.Port)), // #nosec G115
			Priority: 20,
		}}
	}()

	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case res := <-done:
		return res.c, res.err
	case <-t.C:
		return Candidate{}, errors.New("candidate: server-reflexive query timed out")
	case <-ctx.Done():
		return Candidate{}, ctx.Err()
	}
}

// Sort returns cs sorted descending by priority. Stable so equal-priority
// entries keep their input order (host candidates are listed in
// interface order, which is usually the kernel's preferred order).
func Sort(cs []Candidate) []Candidate {
	out := append([]Candidate(nil), cs...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Priority > out[j-1].Priority; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
