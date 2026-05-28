// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package session

// Internal tests for the responder-side warmup punch.
//
// Goal: lock in the behavior that when a Session is constructed on a
// SharedTransport (i.e., the agent was started with --p2p-listen,
// typically the provider role), receiving a CANDIDATE_OFFER causes
// a raw UDP datagram to be sent to every valid peer candidate. This
// is what pre-creates the conntrack entry on the responder's NAT so
// the initiator's later Engine.Check dial traverses port-restricted
// NAT (e.g. CloudStack VR's Linux MASQUERADE) instead of being
// dropped as an unsolicited inbound.
//
// We exercise warmupPunch directly rather than driving a full QUIC
// controlReader: the dispatch site is a single call, and the
// integration of dispatch is covered by the existing CANDIDATE_OFFER
// handling tests. The unique behavior added here is the UDP send.

import (
	"log/slog"
	"net"
	"testing"
	"time"

	orpv1 "github.com/boanlab/OutRelay/lib/orp/v1"
	"github.com/boanlab/OutRelay/lib/transport"
)

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

// TestWarmupPunchNoOpWithoutSharedTransport — when the session's
// dialer is anything other than *SharedTransport (e.g., TCP fallback
// or DefaultDialer-based session), warmupPunch must be a no-op. It
// must not panic, must not attempt UDP, must not log Warn.
func TestWarmupPunchNoOpWithoutSharedTransport(t *testing.T) {
	t.Parallel()

	// Case 1: nil dialer (poked-state session — covers raw construction).
	s1 := &Session{logger: discardLogger()}
	s1.warmupPunch(1, []*orpv1.Candidate{
		{Kind: "host", Ip: "127.0.0.1", Port: 1},
	})

	// Case 2: DefaultDialer (the production path when --p2p-listen is
	// unset). Type assertion against *transport.SharedTransport fails.
	s2 := &Session{logger: discardLogger(), dialer: transport.DefaultDialer{}}
	s2.warmupPunch(1, []*orpv1.Candidate{
		{Kind: "host", Ip: "127.0.0.1", Port: 1},
	})
}

// TestWarmupPunchSendsUDPThroughSharedTransport — the success path.
// Bring up a real SharedTransport on a random localhost port, bring
// up a separate UDP listener as the "peer candidate" target, invoke
// warmupPunch, verify the listener receives the 1-byte payload.
func TestWarmupPunchSendsUDPThroughSharedTransport(t *testing.T) {
	t.Parallel()

	sink, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("sink listen: %v", err)
	}
	defer func() { _ = sink.Close() }()
	sinkAddr := sink.LocalAddr().(*net.UDPAddr)

	received := make(chan []byte, 4)
	go func() {
		buf := make([]byte, 256)
		for {
			n, _, err := sink.ReadFrom(buf)
			if err != nil {
				return
			}
			cp := append([]byte(nil), buf[:n]...)
			received <- cp
		}
	}()

	st, err := transport.NewSharedTransport("127.0.0.1:0")
	if err != nil {
		t.Fatalf("shared transport: %v", err)
	}
	defer func() { _ = st.Close() }()

	s := &Session{logger: discardLogger(), dialer: st}
	s.warmupPunch(0x1234, []*orpv1.Candidate{
		{Kind: "host", Ip: "127.0.0.1", Port: uint32(sinkAddr.Port), Priority: 50},
	})

	select {
	case got := <-received:
		if len(got) != 1 || got[0] != 0x00 {
			t.Fatalf("expected single 0x00 byte payload, got %v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("warmup punch payload was not received on the sink")
	}
}

// TestWarmupPunchSkipsInvalidCandidates — malformed entries (nil,
// empty IP, zero port, > 65535 port, unparseable IP) must be skipped
// without aborting the loop or panicking. The one valid candidate at
// the end must still receive its punch.
func TestWarmupPunchSkipsInvalidCandidates(t *testing.T) {
	t.Parallel()

	sink, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("sink listen: %v", err)
	}
	defer func() { _ = sink.Close() }()
	sinkAddr := sink.LocalAddr().(*net.UDPAddr)

	received := make(chan struct{}, 8)
	go func() {
		buf := make([]byte, 256)
		for {
			if _, _, err := sink.ReadFrom(buf); err != nil {
				return
			}
			received <- struct{}{}
		}
	}()

	st, err := transport.NewSharedTransport("127.0.0.1:0")
	if err != nil {
		t.Fatalf("shared transport: %v", err)
	}
	defer func() { _ = st.Close() }()

	s := &Session{logger: discardLogger(), dialer: st}
	s.warmupPunch(1, []*orpv1.Candidate{
		nil,                            // skipped: nil
		{Ip: "", Port: 100},            // skipped: empty IP
		{Ip: "127.0.0.1", Port: 0},     // skipped: zero port
		{Ip: "127.0.0.1", Port: 70000}, // skipped: port > 65535
		{Ip: "not-an-ip", Port: 100},   // skipped: unparseable IP
		{Ip: "127.0.0.1", Port: uint32(sinkAddr.Port)}, // valid
	})

	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("valid candidate's punch was not delivered")
	}
	// Confirm nothing else arrived from the invalid entries.
	select {
	case <-received:
		t.Fatal("unexpected extra datagram from a skipped candidate")
	case <-time.After(150 * time.Millisecond):
	}
}
