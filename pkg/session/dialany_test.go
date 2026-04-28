// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package session_test

import (
	"crypto/tls"
	"log/slog"
	"testing"
	"time"

	"github.com/boanlab/OutRelay/lib/identity"
	"github.com/boanlab/OutRelay/lib/transport"
	"github.com/boanlab/OutRelay/pkg/pki"

	"github.com/boanlab/outrelay-agent/pkg/session"
)

// TestDialAnyFailoverToHealthy:
//
// Three relay endpoints; the first two are dead, the third runs a
// stub relay. DialAny must skip the failures and connect to the
// healthy endpoint.
func TestDialAnyFailoverToHealthy(t *testing.T) {
	t.Parallel()

	ca, _ := pki.NewCA()
	relayName, _ := identity.NewRelay("acme", "relay-r")
	agentName, _ := identity.NewAgent("acme")
	relayCert := issueCert(t, ca, relayName)
	agentCert := issueCert(t, ca, agentName)

	// Healthy listener.
	healthyTLS := &tls.Config{
		Certificates: []tls.Certificate{*relayCert},
		ClientCAs:    ca.CertPool(),
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
	ln, err := transport.ListenQUIC("127.0.0.1:0", healthyTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	stub := newStubRelay()
	go stub.Run(t.Context(), t, ln)

	agentTLS := &tls.Config{
		Certificates: []tls.Certificate{*agentCert},
		RootCAs:      ca.CertPool(),
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS13,
	}

	// Two unreachable endpoints + one healthy.
	addrs := []string{
		"127.0.0.1:1", // closed
		"127.0.0.1:2", // closed
		ln.Addr().String(),
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		sess, err := session.DialAny(t.Context(), addrs, agentTLS, agentName.String(), slog.New(slog.DiscardHandler))
		if err == nil {
			sess.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("DialAny never reached the healthy endpoint")
}
