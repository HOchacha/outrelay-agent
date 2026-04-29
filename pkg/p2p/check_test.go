// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package p2p_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/boanlab/OutRelay/lib/identity"
	"github.com/boanlab/OutRelay/lib/transport"
	"github.com/boanlab/OutRelay/pkg/pki"

	"github.com/boanlab/outrelay-agent/pkg/candidate"
	"github.com/boanlab/outrelay-agent/pkg/p2p"
)

// TestEngineCheckPicksReachablePair: three candidates — two
// unreachable (closed ports) plus one backed by an in-process QUIC
// listener. Engine.Check must skip the failures and return a
// CheckResult pointing at the live pair.
func TestEngineCheckPicksReachablePair(t *testing.T) {
	t.Parallel()

	ca, _ := pki.NewCA()
	listenerName, _ := identity.NewAgent("acme")
	dialerName, _ := identity.NewAgent("acme")
	listenerCert := issueCert(t, ca, listenerName)
	dialerCert := issueCert(t, ca, dialerName)

	// Listener simulates a peer agent reachable at one of the
	// remote candidates.
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
			_ = c // accept and immediately let it idle; the dialer
			// completes the handshake and the test returns.
		}
	}()

	// Mix of bad + good remote candidates.
	good := mustParseAddrPort(t, ln.Addr().String())
	remotes := []candidate.Candidate{
		{Kind: "host", Addr: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 1), Priority: 70},
		{Kind: "host", Addr: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 2), Priority: 60},
		{Kind: "host", Addr: good, Priority: 50},
	}

	dialerTLS := &tls.Config{
		Certificates: []tls.Certificate{*dialerCert},
		RootCAs:      ca.CertPool(),
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS13,
	}
	eng := p2p.NewEngine(dialerTLS)
	eng.SetPerPairTimeout(300 * time.Millisecond)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	res, err := eng.Check(ctx, nil, remotes)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if res == nil || res.Conn == nil {
		t.Fatal("nil result")
	}
	defer res.Conn.Close()

	if res.Remote.Addr != good {
		t.Fatalf("picked %v, want %v", res.Remote.Addr, good)
	}
	if res.RTT <= 0 {
		t.Fatalf("rtt=%v", res.RTT)
	}
}

// TestEngineCheckAllFail covers the degradation case: no remote
// candidate works — Engine returns ErrNoPair and the caller falls
// back to keeping the stream on the relay.
func TestEngineCheckAllFail(t *testing.T) {
	t.Parallel()
	ca, _ := pki.NewCA()
	dialerName, _ := identity.NewAgent("acme")
	dialerCert := issueCert(t, ca, dialerName)
	dialerTLS := &tls.Config{
		Certificates: []tls.Certificate{*dialerCert},
		RootCAs:      ca.CertPool(),
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS13,
	}
	eng := p2p.NewEngine(dialerTLS)
	eng.SetPerPairTimeout(150 * time.Millisecond)

	remotes := []candidate.Candidate{
		{Kind: "host", Addr: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 1), Priority: 70},
		{Kind: "host", Addr: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 2), Priority: 60},
	}

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if _, err := eng.Check(ctx, nil, remotes); !errors.Is(err, p2p.ErrNoPair) {
		t.Fatalf("got %v, want ErrNoPair", err)
	}
}

func mustParseAddrPort(t *testing.T, s string) netip.AddrPort {
	t.Helper()
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		t.Fatal(err)
	}
	return ap
}

func issueCert(t *testing.T, ca *pki.CA, name identity.Name) *tls.Certificate {
	t.Helper()
	csrDER, key, err := pki.NewCSR(name)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := ca.Sign(csrDER, name, 0)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: key, Leaf: leaf}
}
