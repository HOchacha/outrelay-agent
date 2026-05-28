// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package intercept_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/boanlab/outrelay-agent/pkg/intercept"
)

// TestDNSServerAQuery: bind on an ephemeral UDP port, ask for an A
// record, parse the answer, verify the VIP comes from the allocator.
func TestDNSServerAQuery(t *testing.T) {
	t.Parallel()
	alloc, err := intercept.NewVIPAllocator(intercept.DefaultVIPCIDR)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := intercept.NewDNSServer("127.0.0.1:0", "outrelay", alloc, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	go func() { _ = srv.Run(ctx) }()

	var addr net.Addr
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if a := srv.Addr(); a != nil {
			addr = a
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if addr == nil {
		t.Fatal("dns server never bound")
	}

	// Pre-populate one service. Unknown names will NXDOMAIN.
	want, err := alloc.Allocate("svc-payments")
	if err != nil {
		t.Fatal(err)
	}

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, "udp", addr.String())
		},
	}
	ips, err := resolver.LookupIP(ctx, "ip4", "svc-payments.outrelay")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(ips) != 1 {
		t.Fatalf("got %d IPs, want 1", len(ips))
	}
	if !ips[0].Equal(net.IP(want.AsSlice())) {
		t.Fatalf("got %v want %v", ips[0], want)
	}

	// Unknown name → NXDOMAIN (no auto-allocate on lookup).
	_, err = resolver.LookupIP(ctx, "ip4", "unknown.outrelay")
	if err == nil {
		t.Fatal("expected NXDOMAIN")
	}
}

// TestDNSServerRejectsForeignSuffix: a name that doesn't match the
// configured suffix returns NXDOMAIN even if the bare name is known.
func TestDNSServerRejectsForeignSuffix(t *testing.T) {
	t.Parallel()
	alloc, _ := intercept.NewVIPAllocator(intercept.DefaultVIPCIDR)
	_, _ = alloc.Allocate("svc-a")
	srv, _ := intercept.NewDNSServer("127.0.0.1:0", "outrelay", alloc, nil)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	go func() { _ = srv.Run(ctx) }()
	for srv.Addr() == nil {
		time.Sleep(5 * time.Millisecond)
	}
	addr := srv.Addr().String()

	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return net.Dial("udp", addr)
	}}
	if _, err := r.LookupIP(ctx, "ip4", "svc-a.elsewhere"); err == nil {
		t.Fatal("foreign suffix should be NXDOMAIN")
	}
}
