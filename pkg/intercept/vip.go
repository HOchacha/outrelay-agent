// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package intercept

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
)

// VIPRange is the address pool the allocator hands out. The default is
// CGNAT (100.64.0.0/10), which is unlikely to clash with real workloads
// and is what tools like Tailscale use for the same purpose.
const DefaultVIPCIDR = "100.64.0.0/10"

// VIPAllocator hands out unique IPs within a CIDR for service names,
// and supports the reverse lookup tproxy needs (vip -> service name).
type VIPAllocator struct {
	prefix   netip.Prefix
	mu       sync.Mutex
	nameToIP map[string]netip.Addr
	ipToName map[netip.Addr]string
	next     netip.Addr
}

// NewVIPAllocator parses cidr and returns a fresh allocator.
// Use DefaultVIPCIDR for the standard CGNAT range.
func NewVIPAllocator(cidr string) (*VIPAllocator, error) {
	pfx, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("intercept: parse %q: %w", cidr, err)
	}
	if !pfx.Addr().Is4() {
		return nil, errors.New("intercept: only IPv4 VIP ranges supported")
	}
	// Skip the network address; first VIP is .1.
	return &VIPAllocator{
		prefix:   pfx.Masked(),
		nameToIP: map[string]netip.Addr{},
		ipToName: map[netip.Addr]string{},
		next:     pfx.Masked().Addr().Next(),
	}, nil
}

// Allocate returns the VIP for the given service name, allocating a
// fresh one if the name is unseen. Same name -> same VIP across calls.
//
// The agent calls Allocate at startup for every service in its consume
// list. The DNS server uses LookupName (no side effects) so that
// queries for unknown names return NXDOMAIN instead of accidentally
// allocating new entries.
func (a *VIPAllocator) Allocate(name string) (netip.Addr, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if ip, ok := a.nameToIP[name]; ok {
		return ip, nil
	}
	for {
		if !a.prefix.Contains(a.next) {
			return netip.Addr{}, errors.New("intercept: VIP pool exhausted")
		}
		ip := a.next
		a.next = a.next.Next()
		// Skip broadcast / "all-ones" host addresses by simple heuristic.
		if !isUsable(ip) {
			continue
		}
		if _, taken := a.ipToName[ip]; taken {
			continue
		}
		a.nameToIP[name] = ip
		a.ipToName[ip] = name
		return ip, nil
	}
}

// LookupName returns the previously allocated VIP for name, or
// (zero, false) if no allocation has been made.
func (a *VIPAllocator) LookupName(name string) (netip.Addr, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ip, ok := a.nameToIP[name]
	return ip, ok
}

// Lookup reverses an allocated VIP back to a service name, or returns
// "" if vip is not known.
func (a *VIPAllocator) Lookup(vip netip.Addr) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.ipToName[vip]
}

// Len returns the number of allocated VIPs.
func (a *VIPAllocator) Len() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.nameToIP)
}

// isUsable rejects the .0 / .255 (subnet broadcast / network) of each
// /24 block. CGNAT is /10 so we don't enforce strict broadcast on the
// outer prefix; this is a cheap heuristic for sanity.
func isUsable(ip netip.Addr) bool {
	b := ip.As4()
	if b[3] == 0 || b[3] == 255 {
		return false
	}
	return true
}
