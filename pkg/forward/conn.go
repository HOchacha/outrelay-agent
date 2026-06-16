// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

// Package forward implements the agent side of the relay's
// mini-TURN data plane (relay_mode=FORWARD).
//
// Conn is a net.PacketConn that an agent sits on top of via
// quic.Transport. Every WriteTo prepends a 4-byte big-endian
// peer_alloc id and sends the packet to the relay's forwarding
// endpoint (regardless of the addr passed in by quic-go). Every
// ReadFrom reads a packet whose 4-byte prefix the relay already
// stripped, and reports the relay's address as the "remote" so
// quic-go's connection map sees a stable remote per connection.
//
// Bootstrap: Dial sends a registration packet (peer_alloc=0,
// payload=[my_alloc][punch_nonce]) so the relay records
// (my_alloc -> our UDP src). The nonce must match what the agent
// also sent on the control plane via FrameTypeForwardRegister —
// the relay's pending entry binds the two halves together and
// rejects a punch whose nonce doesn't match. After registration
// the conn is ready for quic.Transport to layer end-to-end QUIC.

package forward

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"time"
)

// DefaultIdleTimeout is the recommended argument to WatchIdle. It
// comfortably outlives one or two e2e QUIC keepalive intervals so a
// healthy relay+peer doesn't trip it, but cuts the agent off well
// before the e2e QUIC connection's own idle timeout (which can be
// 30s–2min depending on quic-go defaults) and stops the agent from
// burning the relay's "drop (alloc not registered)" log spam if the
// relay's allocation has been wiped (e.g., relay restart).
const DefaultIdleTimeout = 20 * time.Second

// PunchNonceSize is the byte length of the random nonce embedded in
// both the control-plane FrameTypeForwardRegister and the UDP punch.
// Keep in sync with relay's forward.PunchNonceSize.
const PunchNonceSize = 16

// Conn satisfies net.PacketConn. quic.Transport uses it as its
// underlying socket.
type Conn struct {
	udp        *net.UDPConn
	relay      netip.AddrPort
	relayAddr  net.Addr // pre-computed for ReadFrom's return
	peerAlloc  uint32
	myAlloc    uint32
	punchNonce [PunchNonceSize]byte
	logger     *slog.Logger

	// lastInbound is the unix-nano timestamp of the most recent
	// successful ReadFrom. WatchIdle reads this atomically to decide
	// whether to close the conn.
	lastInbound atomic.Int64
}

// Dial opens a UDP socket, registers myAlloc with the relay's
// forwarding plane at relayAddr, and returns a Conn keyed to send
// to the peer's allocation. The Conn satisfies net.PacketConn for
// quic.Transport.
//
// punchNonce is the 16-byte random the caller must have already sent
// to the relay on the control plane via FrameTypeForwardRegister:
// the relay binds (alloc -> our UDP src) only after the two halves
// land and their nonces match.
func Dial(relay netip.AddrPort, myAlloc, peerAlloc uint32, punchNonce [PunchNonceSize]byte) (*Conn, error) {
	return DialWithLogger(relay, myAlloc, peerAlloc, punchNonce, nil)
}

// DialWithLogger is Dial with an explicit logger. A nil logger
// disables logging.
func DialWithLogger(relay netip.AddrPort, myAlloc, peerAlloc uint32, punchNonce [PunchNonceSize]byte, logger *slog.Logger) (*Conn, error) {
	if myAlloc == 0 || peerAlloc == 0 {
		return nil, errors.New("forward: alloc ids must be non-zero")
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		logger.Warn("forward: bind local UDP failed", "err", err)
		return nil, fmt.Errorf("forward: bind local UDP: %w", err)
	}
	c := &Conn{
		udp:        udp,
		relay:      relay,
		relayAddr:  net.UDPAddrFromAddrPort(relay),
		peerAlloc:  peerAlloc,
		myAlloc:    myAlloc,
		punchNonce: punchNonce,
		logger:     logger,
	}
	if err := c.register(); err != nil {
		_ = udp.Close()
		return nil, err
	}
	return c, nil
}

func (c *Conn) register() error {
	buf := make([]byte, 8+PunchNonceSize)
	binary.BigEndian.PutUint32(buf[0:4], 0) // peer_alloc=0 = registration
	binary.BigEndian.PutUint32(buf[4:8], c.myAlloc)
	copy(buf[8:], c.punchNonce[:])
	if _, err := c.udp.WriteToUDPAddrPort(buf, c.relay); err != nil {
		c.logger.Warn("forward: register failed",
			"relay", c.relay.String(), "my_alloc", c.myAlloc, "err", err)
		return fmt.Errorf("forward: register: %w", err)
	}
	c.logger.Info("forward: registered with relay",
		"relay", c.relay.String(), "my_alloc", c.myAlloc, "peer_alloc", c.peerAlloc)
	return nil
}

// WriteTo prepends peer_alloc to p and ships to the relay. The
// addr argument is ignored — quic-go's choice of "remote" doesn't
// matter; everything goes to the relay. Returns len(p) on success
// (caller's bookkeeping operates on payload bytes, not wire bytes).
func (c *Conn) WriteTo(p []byte, _ net.Addr) (int, error) {
	buf := make([]byte, 4+len(p))
	binary.BigEndian.PutUint32(buf[0:4], c.peerAlloc)
	copy(buf[4:], p)
	if _, err := c.udp.WriteToUDPAddrPort(buf, c.relay); err != nil {
		return 0, err
	}
	return len(p), nil
}

// ReadFrom reads one forwarded packet. The relay has already
// stripped its 4-byte prefix so the bytes are exactly what the
// peer's WriteTo handed in. The returned addr is the relay's
// endpoint — quic-go uses it as the connection's stable "remote"
// for the lifetime of the connection.
//
// Successful reads bump an internal lastInbound timestamp consumed
// by WatchIdle for dead-path detection.
func (c *Conn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, _, err := c.udp.ReadFromUDPAddrPort(p)
	if err != nil {
		return 0, nil, err
	}
	c.lastInbound.Store(time.Now().UnixNano())
	return n, c.relayAddr, nil
}

// WatchIdle starts a background goroutine that closes this Conn if
// no inbound packet has been observed for idleTimeout. Use this to
// fail fast when the relay restarts (or otherwise wipes our
// allocation): the e2e QUIC tunnel layered on top sees the closed
// socket as an unrecoverable error and the caller's bridge exits,
// letting the application decide whether to redial.
//
// The watcher is armed at call time (treats "now" as the most recent
// inbound) so a freshly-Dialed Conn doesn't immediately trip while
// the e2e QUIC handshake is still in flight. Stop the watcher by
// cancelling ctx or by calling Close — either causes the goroutine
// to return on its next tick.
//
// Idempotency: WatchIdle may be called more than once but each call
// spawns a new watcher; callers should invoke it exactly once
// per Conn lifetime.
func (c *Conn) WatchIdle(ctx context.Context, idleTimeout time.Duration) {
	if idleTimeout <= 0 {
		return
	}
	c.lastInbound.Store(time.Now().UnixNano())
	interval := idleTimeout / 4
	if interval < time.Second {
		interval = time.Second
	}
	if interval > 5*time.Second {
		interval = 5 * time.Second
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		thresholdNs := idleTimeout.Nanoseconds()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				last := c.lastInbound.Load()
				if last == 0 {
					continue
				}
				idleNs := now.UnixNano() - last
				if idleNs <= thresholdNs {
					continue
				}
				c.logger.Warn("forward: conn idle, closing",
					"my_alloc", c.myAlloc, "peer_alloc", c.peerAlloc,
					"idle_s", idleNs/int64(time.Second))
				_ = c.udp.Close()
				return
			}
		}
	}()
}

func (c *Conn) LocalAddr() net.Addr                { return c.udp.LocalAddr() }
func (c *Conn) Close() error                       { return c.udp.Close() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.udp.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.udp.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.udp.SetWriteDeadline(t) }

// PeerSentinel is the synthetic remote address quic.Transport.Dial
// must be passed when dialing a peer over a Conn. Any non-nil addr
// works because Conn.WriteTo ignores it; this constant just gives
// callers something to pass that documents the intent.
var PeerSentinel = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 0), Port: 1}
