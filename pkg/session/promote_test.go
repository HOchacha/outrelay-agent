// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package session_test

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/boanlab/OutRelay/lib/identity"
	"github.com/boanlab/OutRelay/lib/orp"
	orpv1 "github.com/boanlab/OutRelay/lib/orp/v1"
	"github.com/boanlab/OutRelay/lib/transport"
	"github.com/boanlab/OutRelay/pkg/pki"

	"github.com/boanlab/outrelay-agent/pkg/candidate"
	"github.com/boanlab/outrelay-agent/pkg/p2p"
	"github.com/boanlab/outrelay-agent/pkg/session"
)

// TestSessionPromoteAndMigrate:
//
// Initiator session calls Promote against a stream id; the test's
// stub relay forwards the OFFER to a "responder" agent, which
// immediately replies with an ANSWER advertising a local QUIC
// listener. Promote completes, returning a live direct conn.
// MigrateToDirect opens a fresh stream on the direct conn and writes
// STREAM_RESUME, swapping the ResumableStream's inner.
//
// This validates the §3.19 OFFER/ANSWER plumbing plus the Stream
// Migrator (§3.19.5) end-to-end without needing the relay binary or
// the responder's full session machinery.
func TestSessionPromoteAndMigrate(t *testing.T) {
	t.Parallel()

	ca, _ := pki.NewCA()

	// Direct-path listener that simulates the peer agent's reachable
	// endpoint.
	peerListenerName, _ := identity.NewAgent("acme")
	peerListenerCert := issueCert(t, ca, peerListenerName)
	listenerTLS := &tls.Config{
		Certificates: []tls.Certificate{*peerListenerCert},
		ClientCAs:    ca.CertPool(),
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
	directLn, err := transport.ListenQUIC("127.0.0.1:0", listenerTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer directLn.Close()

	// Direct listener accepts the migrated stream and reads its first
	// frame — the STREAM_RESUME payload that the Stream Migrator wrote.
	type resumeOut struct {
		f   *orpv1.StreamResume
		err error
	}
	resumeCh := make(chan resumeOut, 1)
	go func() {
		c, err := directLn.Accept(t.Context())
		if err != nil {
			resumeCh <- resumeOut{err: err}
			return
		}
		st, err := c.AcceptStream(t.Context())
		if err != nil {
			resumeCh <- resumeOut{err: err}
			return
		}
		f, err := orp.ParseFrame(st)
		if err != nil {
			resumeCh <- resumeOut{err: err}
			return
		}
		out := &orpv1.StreamResume{}
		if err := orp.UnmarshalProto(f, orp.FrameTypeStreamResume, out); err != nil {
			resumeCh <- resumeOut{err: err}
			return
		}
		resumeCh <- resumeOut{f: out}
	}()

	// Stub relay used by the initiator's Session — it terminates HELLO,
	// REGISTER (skipped here), and forwards CANDIDATE_OFFER as a
	// CANDIDATE_ANSWER pointing at directLn.
	relayName, _ := identity.NewRelay("acme", "relay-r")
	relayCert := issueCert(t, ca, relayName)
	relayTLS := &tls.Config{
		Certificates: []tls.Certificate{*relayCert},
		ClientCAs:    ca.CertPool(),
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
	relayLn, err := transport.ListenQUIC("127.0.0.1:0", relayTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer relayLn.Close()

	directAddr, _ := netip.ParseAddrPort(directLn.Addr().String())
	go runOfferAnswerStubRelay(t, relayLn, directAddr)

	// Initiator session.
	initName, _ := identity.NewAgent("acme")
	initCert := issueCert(t, ca, initName)
	initTLS := &tls.Config{
		Certificates: []tls.Certificate{*initCert},
		RootCAs:      ca.CertPool(),
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS13,
	}
	sess, err := session.Dial(t.Context(), relayLn.Addr().String(), initTLS, initName.String(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	enableCtx, enableCancel := context.WithCancel(t.Context())
	defer enableCancel()
	sess.EnableP2P(enableCtx)

	// Open a stream so we have a ResumableStream to migrate. The
	// stub relay doesn't actually splice; we don't care because the
	// test only exercises promotion + migration, not data transfer.
	rs, err := sess.Dial(t.Context(), "svc-x", "")
	if err != nil {
		t.Fatal(err)
	}

	// Promote.
	dialerTLS := &tls.Config{
		Certificates: []tls.Certificate{*initCert},
		RootCAs:      ca.CertPool(),
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS13,
	}
	eng := p2p.NewEngine(dialerTLS)
	eng.SetPerPairTimeout(500 * time.Millisecond)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	res, err := sess.Promote(ctx, rs, eng, session.PromoteOptions{
		HostPort: 0,
		Locals: []candidate.Candidate{
			{Kind: "host", Addr: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 50000), Priority: 70},
		},
	})
	if err != nil {
		t.Fatalf("Promote: %v", err)
	}
	if res == nil || res.Conn == nil {
		t.Fatal("nil result")
	}
	defer res.Conn.Close()

	if err := sess.MigrateToDirect(ctx, rs, res.Conn); err != nil {
		t.Fatalf("MigrateToDirect: %v", err)
	}

	// The direct listener should have received STREAM_RESUME with the
	// matching stream id.
	select {
	case got := <-resumeCh:
		if got.err != nil {
			t.Fatalf("listener: %v", got.err)
		}
		if got.f.StreamId != uint64(rs.StreamID()) {
			t.Fatalf("stream_id mismatch: got %d, want %d", got.f.StreamId, rs.StreamID())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("STREAM_RESUME never reached the direct listener")
	}
}

// runOfferAnswerStubRelay terminates initiator HELLO, accepts a
// stream that carries OPEN_STREAM (so Session.Dial returns), then
// reads CANDIDATE_OFFER off the control stream and writes back a
// CANDIDATE_ANSWER advertising the direct listener.
func runOfferAnswerStubRelay(t *testing.T, ln transport.Listener, directAddr netip.AddrPort) {
	t.Helper()
	ctx := context.Background()

	conn, err := ln.Accept(ctx)
	if err != nil {
		return
	}
	ctrl, err := conn.AcceptStream(ctx)
	if err != nil {
		return
	}
	hf, err := orp.ParseFrame(ctrl)
	if err != nil || hf.Type != orp.FrameTypeHello {
		return
	}
	if err := orp.WriteFrame(ctrl, orp.FrameTypeHelloAck, &orpv1.HelloAck{}); err != nil {
		return
	}

	// Drain incoming streams from the initiator (e.g. OPEN_STREAM
	// from sess.Dial). We just hold them open silently.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			s, err := conn.AcceptStream(ctx)
			if err != nil {
				return
			}
			go func(s transport.Stream) {
				_, _ = orp.ParseFrame(s) // read OPEN_STREAM, then idle
			}(s)
		}
	}()

	// Read frames off the control stream. On CANDIDATE_OFFER, reply
	// with a single-candidate ANSWER pointing at directAddr.
	for {
		f, err := orp.ParseFrame(ctrl)
		if err != nil {
			return
		}
		if f.Type != orp.FrameTypeCandidateOffer && f.Type != orp.FrameTypeMigrateToP2P {
			continue
		}
		if f.Type == orp.FrameTypeMigrateToP2P {
			// Initiator told us about migration; ignore.
			continue
		}
		offer := &orpv1.CandidateOffer{}
		if err := orp.UnmarshalProto(f, orp.FrameTypeCandidateOffer, offer); err != nil {
			continue
		}
		_ = orp.WriteFrame(ctrl, orp.FrameTypeCandidateAnswer, &orpv1.CandidateAnswer{
			StreamId: offer.StreamId,
			Candidates: []*orpv1.Candidate{
				{Kind: "host", Ip: directAddr.Addr().String(), Port: uint32(directAddr.Port()), Priority: 70},
			},
		})
	}
}
