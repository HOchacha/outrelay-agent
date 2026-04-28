// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package candidate_test

import (
	"net/netip"
	"testing"

	"github.com/boanlab/outrelay-agent/pkg/candidate"
)

func TestHostCandidatesNonEmpty(t *testing.T) {
	t.Parallel()
	cs := candidate.HostCandidates(7443)
	if len(cs) == 0 {
		t.Skip("no usable interface addresses on this host (likely a sandboxed test runner)")
	}
	for _, c := range cs {
		if c.Kind != "host" {
			t.Errorf("kind=%q want host", c.Kind)
		}
		if !c.Addr.IsValid() || c.Addr.Port() != 7443 {
			t.Errorf("bad addr %v", c.Addr)
		}
	}
}

func TestSortByPriorityDesc(t *testing.T) {
	t.Parallel()
	in := []candidate.Candidate{
		{Kind: "srflx", Addr: ap("203.0.113.5", 7443), Priority: 20},
		{Kind: "host", Addr: ap("10.0.0.1", 7443), Priority: 30},
		{Kind: "host", Addr: ap("172.16.0.1", 7443), Priority: 30},
		{Kind: "host", Addr: ap("198.51.100.5", 7443), Priority: 70},
	}
	out := candidate.Sort(in)
	wantOrder := []uint32{70, 30, 30, 20}
	for i, c := range out {
		if c.Priority != wantOrder[i] {
			t.Fatalf("position %d: got prio=%d want %d", i, c.Priority, wantOrder[i])
		}
	}
}

func ap(s string, port uint16) netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr(s), port)
}
