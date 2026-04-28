// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package p2p_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/boanlab/OutRelay/lib/identity"
	orpv1 "github.com/boanlab/OutRelay/lib/orp/v1"
	"github.com/boanlab/OutRelay/lib/transport"
	"github.com/boanlab/OutRelay/pkg/pki"

	"github.com/boanlab/outrelay-agent/pkg/candidate"
	"github.com/boanlab/outrelay-agent/pkg/p2p"
)

// TestPromoterHappyPath: Promoter sends OFFER, receives ANSWER, runs
// the connectivity check, and signals MIGRATE_TO_P2P. Hooks are mocked
// with channels; the peer "ANSWER" advertises a candidate that
// resolves to an in-process QUIC listener, so the connectivity check
// picks it.
func TestPromoterHappyPath(t *testing.T) {
	t.Parallel()

	ca, _ := pki.NewCA()
	listenerName, _ := identity.NewAgent("acme")
	dialerName, _ := identity.NewAgent("acme")
	listenerCert := issueCert(t, ca, listenerName)
	dialerCert := issueCert(t, ca, dialerName)

	// Stand up a P2P listener that simulates the peer agent's
	// reachable endpoint.
	listenerTLS := &tls.Config{
		Certificates: []tls.Certificate{*listenerCert},
		ClientCAs:    ca.CertPool(),
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
	ln, err := transport.ListenQUIC("127.0.0.1:0", listenerTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept(t.Context())
			if err != nil {
				return
			}
			_ = c
		}
	}()

	dialerTLS := &tls.Config{
		Certificates: []tls.Certificate{*dialerCert},
		RootCAs:      ca.CertPool(),
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS13,
	}
	engine := p2p.NewEngine(dialerTLS)
	engine.SetPerPairTimeout(300 * time.Millisecond)

	const streamID uint64 = 0xa11ce

	offerCh := make(chan *orpv1.CandidateOffer, 1)
	answerCh := make(chan *orpv1.CandidateAnswer, 1)
	migrateCh := make(chan *orpv1.MigrateToP2P, 1)

	good := mustParseAP(t, ln.Addr().String())
	pr := &p2p.Promoter{
		StreamID: streamID,
		Engine:   engine,
		Locals: []candidate.Candidate{
			{Kind: "host", Addr: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 50000), Priority: 70},
		},
		SendOffer: func(o *orpv1.CandidateOffer) error {
			offerCh <- o
			return nil
		},
		RecvAnswer: func(ctx context.Context) (*orpv1.CandidateAnswer, error) {
			select {
			case a := <-answerCh:
				return a, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
		SendMigrate: func(m *orpv1.MigrateToP2P) error {
			migrateCh <- m
			return nil
		},
	}

	// Drive the peer side: read the OFFER, reply with ANSWER pointing
	// at the live listener.
	go func() {
		o := <-offerCh
		if o.StreamId != streamID {
			t.Errorf("offer stream_id=%d", o.StreamId)
		}
		answerCh <- &orpv1.CandidateAnswer{
			StreamId: streamID,
			Candidates: []*orpv1.Candidate{
				{Kind: "host", Ip: good.Addr().String(), Port: uint32(good.Port()), Priority: 70},
			},
		}
	}()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	res, err := pr.Run(ctx)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res == nil || res.Conn == nil {
		t.Fatal("nil result")
	}
	defer res.Conn.Close()
	if res.Remote.Addr != good {
		t.Fatalf("picked %v, want %v", res.Remote.Addr, good)
	}

	select {
	case m := <-migrateCh:
		if m.StreamId != streamID {
			t.Fatalf("migrate stream_id=%d", m.StreamId)
		}
		if m.Selected == nil || m.Selected.Ip != good.Addr().String() {
			t.Fatalf("selected mismatch: %+v", m.Selected)
		}
	case <-time.After(time.Second):
		t.Fatal("MIGRATE_TO_P2P never sent")
	}
}

// TestPromoterAnswerStreamIDMismatch: peer answer for the wrong
// stream id surfaces as an error and the promoter does not run the
// check.
func TestPromoterAnswerStreamIDMismatch(t *testing.T) {
	t.Parallel()
	pr := &p2p.Promoter{
		StreamID:  100,
		Engine:    p2p.NewEngine(&tls.Config{MinVersion: tls.VersionTLS13}),
		SendOffer: func(*orpv1.CandidateOffer) error { return nil },
		RecvAnswer: func(context.Context) (*orpv1.CandidateAnswer, error) {
			return &orpv1.CandidateAnswer{StreamId: 999}, nil
		},
	}
	if _, err := pr.Run(t.Context()); err == nil {
		t.Fatal("expected error on stream_id mismatch")
	}
}

// TestPromoterMisconfigured: nil hook → ErrPromoterMisconfigured.
func TestPromoterMisconfigured(t *testing.T) {
	t.Parallel()
	pr := &p2p.Promoter{}
	if _, err := pr.Run(t.Context()); !errors.Is(err, p2p.ErrPromoterMisconfigured) {
		t.Fatalf("got %v, want ErrPromoterMisconfigured", err)
	}
}

func mustParseAP(t *testing.T, s string) netip.AddrPort {
	t.Helper()
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		t.Fatal(err)
	}
	return ap
}
