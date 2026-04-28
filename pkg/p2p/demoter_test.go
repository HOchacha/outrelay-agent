// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package p2p_test

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/boanlab/OutRelay/lib/identity"
	"github.com/boanlab/OutRelay/lib/transport"
	"github.com/boanlab/OutRelay/pkg/pki"

	"github.com/boanlab/outrelay-agent/pkg/p2p"
)

// TestDemoterFiresOnPeerClose: run the Demoter against a live P2P
// conn, then close the listener side. AcceptStream returns an error
// and OnDegrade fires once with DemoteReasonPeerClose.
func TestDemoterFiresOnPeerClose(t *testing.T) {
	t.Parallel()

	ca, _ := pki.NewCA()
	listenerName, _ := identity.NewAgent("acme")
	dialerName, _ := identity.NewAgent("acme")
	listenerCert := issueCert(t, ca, listenerName)
	dialerCert := issueCert(t, ca, dialerName)

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

	// Listener accepts one conn then closes when we close ln.
	var serverConn transport.Conn
	var serverWG sync.WaitGroup
	serverWG.Add(1)
	go func() {
		defer serverWG.Done()
		c, err := ln.Accept(t.Context())
		if err != nil {
			return
		}
		serverConn = c
	}()

	dialerTLS := &tls.Config{
		Certificates: []tls.Certificate{*dialerCert},
		RootCAs:      ca.CertPool(),
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS13,
	}
	conn, err := transport.DialQUIC(t.Context(), ln.Addr().String(), dialerTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	serverWG.Wait()

	var fired atomic.Int32
	var capturedReason atomic.Pointer[p2p.DemoteReason]
	d := &p2p.Demoter{
		Conn: conn,
		OnDegrade: func(r p2p.DemoteReason, err error) {
			fired.Add(1)
			rc := r
			capturedReason.Store(&rc)
		},
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()

	// Force the peer side to close.
	if serverConn != nil {
		_ = serverConn.Close()
	}
	_ = ln.Close()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Demoter did not return after peer close")
	}

	if fired.Load() != 1 {
		t.Fatalf("OnDegrade fired %d times, want 1", fired.Load())
	}
	if r := capturedReason.Load(); r == nil || *r != p2p.DemoteReasonPeerClose {
		t.Fatalf("reason mismatch: %v", capturedReason.Load())
	}
}

// TestDemoterMisconfigured: nil conn / hook → ErrDemoterMisconfigured.
func TestDemoterMisconfigured(t *testing.T) {
	t.Parallel()
	d := &p2p.Demoter{}
	if err := d.Run(t.Context()); !errors.Is(err, p2p.ErrDemoterMisconfigured) {
		t.Fatalf("got %v, want ErrDemoterMisconfigured", err)
	}
}
