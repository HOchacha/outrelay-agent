// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package forward

// Tests for WatchIdle's dead-path detection.
//
// When the relay's forwarding plane stops returning packets (e.g.,
// relay restart wiped the agent's allocation), the agent's Conn keeps
// sending into a black hole until the e2e QUIC connection eventually
// idles out — which can be tens of seconds to minutes. WatchIdle
// shortens that by closing the UDP socket once no inbound packet has
// been observed for the configured window; the e2e QUIC layer then
// sees a hard transport error and the application can fail fast.

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestWatchIdleClosesOnSilence — with no inbound packets ever, the
// watcher fires and closes the UDP socket within roughly the idle
// timeout window.
func TestWatchIdleClosesOnSilence(t *testing.T) {
	t.Parallel()

	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	c := &Conn{udp: udp, logger: testLogger()}

	idle := 200 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.WatchIdle(ctx, idle)

	// Close should happen within ~idle + interval (interval >= 1s by
	// the floor inside WatchIdle). Allow generous margin to avoid
	// flake on slow CI.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		// Detect close by attempting a write.
		if _, err := udp.WriteToUDPAddrPort([]byte{0}, udp.LocalAddr().(*net.UDPAddr).AddrPort()); err != nil {
			return // closed — success
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("WatchIdle did not close the socket within deadline")
}

// TestWatchIdleStaysOpenWithInbound — periodic ReadFrom success
// (simulated by bumping lastInbound directly) prevents the watcher
// from firing. Mirrors the production path where e2e QUIC keepalives
// keep datagrams flowing as long as the relay is alive.
func TestWatchIdleStaysOpenWithInbound(t *testing.T) {
	t.Parallel()

	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer func() { _ = udp.Close() }()
	c := &Conn{udp: udp, logger: testLogger()}

	idle := 200 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.WatchIdle(ctx, idle)

	// Bump lastInbound every 50ms for 1s; idle window never lapses.
	stop := time.After(1 * time.Second)
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
loop:
	for {
		select {
		case <-stop:
			break loop
		case <-tick.C:
			c.lastInbound.Store(time.Now().UnixNano())
		}
	}

	// Socket should still be alive.
	if _, err := udp.WriteToUDPAddrPort([]byte{0}, udp.LocalAddr().(*net.UDPAddr).AddrPort()); err != nil {
		t.Fatalf("socket unexpectedly closed: %v", err)
	}
}

// TestWatchIdleZeroTimeoutIsNoOp — passing 0 should not spawn a
// watcher (and not panic). Verified by ensuring the socket survives
// well past where a watcher would have fired.
func TestWatchIdleZeroTimeoutIsNoOp(t *testing.T) {
	t.Parallel()

	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer func() { _ = udp.Close() }()
	c := &Conn{udp: udp, logger: testLogger()}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.WatchIdle(ctx, 0)

	time.Sleep(300 * time.Millisecond)
	if _, err := udp.WriteToUDPAddrPort([]byte{0}, udp.LocalAddr().(*net.UDPAddr).AddrPort()); err != nil {
		t.Fatalf("zero-timeout WatchIdle should not close socket: %v", err)
	}
}

// TestReadFromBumpsLastInbound — successful ReadFrom updates the
// atomic timestamp WatchIdle consults.
func TestReadFromBumpsLastInbound(t *testing.T) {
	t.Parallel()

	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer func() { _ = udp.Close() }()

	c := &Conn{
		udp:       udp,
		relayAddr: udp.LocalAddr(),
		logger:    testLogger(),
	}

	// Send a packet to our own socket so ReadFrom returns.
	if _, err := udp.WriteToUDPAddrPort(
		[]byte("hi"),
		udp.LocalAddr().(*net.UDPAddr).AddrPort(),
	); err != nil {
		t.Fatalf("send: %v", err)
	}

	before := c.lastInbound.Load()
	buf := make([]byte, 32)
	_ = udp.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := c.ReadFrom(buf); err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	after := c.lastInbound.Load()
	if !(after > before) {
		t.Fatalf("lastInbound did not advance: before=%d after=%d", before, after)
	}
}

// silence-check for atomic.Int64 import (the import is otherwise only
// touched by Conn.lastInbound, which we read with .Load() — keeps the
// linter happy if more tests are added that use atomic directly).
var _ atomic.Int64
