// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package intercept_test

import (
	"net/netip"
	"testing"

	"github.com/boanlab/outrelay-agent/pkg/intercept"
)

func TestVIPAllocateStable(t *testing.T) {
	t.Parallel()
	a, err := intercept.NewVIPAllocator(intercept.DefaultVIPCIDR)
	if err != nil {
		t.Fatal(err)
	}
	first, err := a.Allocate("svc-x")
	if err != nil {
		t.Fatal(err)
	}
	again, err := a.Allocate("svc-x")
	if err != nil {
		t.Fatal(err)
	}
	if first != again {
		t.Fatalf("same name should yield same VIP: got %v then %v", first, again)
	}
	other, err := a.Allocate("svc-y")
	if err != nil {
		t.Fatal(err)
	}
	if other == first {
		t.Fatal("different names must yield different VIPs")
	}
	if a.Lookup(first) != "svc-x" {
		t.Fatalf("reverse lookup mismatch")
	}
	if a.Lookup(other) != "svc-y" {
		t.Fatalf("reverse lookup mismatch")
	}
	if a.Len() != 2 {
		t.Fatalf("Len=%d want 2", a.Len())
	}
}

func TestVIPInsideCIDR(t *testing.T) {
	t.Parallel()
	a, _ := intercept.NewVIPAllocator(intercept.DefaultVIPCIDR)
	cidr, _ := netip.ParsePrefix(intercept.DefaultVIPCIDR)
	for _, name := range []string{"a", "b", "c", "d", "e"} {
		vip, err := a.Allocate(name)
		if err != nil {
			t.Fatal(err)
		}
		if !cidr.Contains(vip) {
			t.Fatalf("VIP %v outside %v", vip, cidr)
		}
	}
}

func TestVIPLookupUnknown(t *testing.T) {
	t.Parallel()
	a, _ := intercept.NewVIPAllocator(intercept.DefaultVIPCIDR)
	got := a.Lookup(netip.MustParseAddr("100.64.99.99"))
	if got != "" {
		t.Fatalf("unknown VIP should return empty, got %q", got)
	}
}
