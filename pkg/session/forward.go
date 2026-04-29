// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package session

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/quic-go/quic-go"

	orpv1 "github.com/boanlab/OutRelay/lib/orp/v1"
	"github.com/boanlab/OutRelay/lib/transport"

	"github.com/boanlab/outrelay-agent/pkg/forward"
)

// ForwardSession is the agent-side container for one stream's
// relay_mode=FORWARD data path. It owns the registered UDP socket
// (forward.Conn) talking to the relay's mini-TURN plane, the e2e
// quic.Transport sitting on top, and the QUIC connection +
// application stream the bridge actually reads/writes.
//
// Close releases everything in order — stream first (so peer sees
// end-of-stream), then connection, then transport, then the
// underlying socket.
type ForwardSession struct {
	conn      transport.Conn
	stream    transport.Stream
	transport *quic.Transport
	udp       *forward.Conn
}

// Stream returns the bidirectional application stream for this
// forward session.
func (f *ForwardSession) Stream() transport.Stream { return f.stream }

// Conn returns the e2e QUIC connection (rarely needed; mostly for
// instrumentation).
func (f *ForwardSession) Conn() transport.Conn { return f.conn }

// Close tears down the forward session in the order that minimises
// "connection closed" log noise on the peer.
func (f *ForwardSession) Close() error {
	var first error
	if f.stream != nil {
		if err := f.stream.Close(); err != nil && first == nil {
			first = err
		}
	}
	if f.conn != nil {
		if err := f.conn.Close(); err != nil && first == nil {
			first = err
		}
	}
	if f.transport != nil {
		if err := f.transport.Close(); err != nil && first == nil {
			first = err
		}
	}
	if f.udp != nil {
		if err := f.udp.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// DialForward is the consumer-side bring-up: takes the AllocGranted
// the relay sent on the agent's ctrl, opens the relay-mediated UDP
// socket to the forwarding plane, and runs an e2e QUIC handshake
// over it against the peer agent (which is running AcceptForward on
// its side). Returns a ForwardSession the caller bridges to its
// local intercept.Conn.
//
// tlsConf is the agent's client TLS config (cert + RootCAs). Because
// quic-go's Transport.Dial requires a remote address but our packet
// conn forces every WriteTo to the relay, we pass forward.PeerSentinel
// — the value documents intent and quic-go uses it as the connection's
// stable "remote" identity.
//
// ALPN must match what the listener side advertises (see ALPN below).
func DialForward(
	ctx context.Context,
	granted *orpv1.AllocGranted,
	tlsConf *tls.Config,
) (*ForwardSession, error) {
	if granted == nil || granted.MyAllocation == 0 || granted.PeerAllocation == 0 {
		return nil, errors.New("session: invalid AllocGranted")
	}
	relay, err := netip.ParseAddrPort(granted.ForwardEndpoint)
	if err != nil {
		return nil, fmt.Errorf("session: parse forward endpoint %q: %w", granted.ForwardEndpoint, err)
	}
	udp, err := forward.Dial(relay, granted.MyAllocation, granted.PeerAllocation)
	if err != nil {
		return nil, err
	}
	tr := &quic.Transport{Conn: udp}

	tlsConf = ensureForwardALPN(tlsConf)
	qc, err := tr.Dial(ctx, forward.PeerSentinel, tlsConf, defaultQUICConfig())
	if err != nil {
		_ = tr.Close()
		_ = udp.Close()
		return nil, fmt.Errorf("session: forward dial: %w", err)
	}
	st, err := qc.OpenStreamSync(ctx)
	if err != nil {
		_ = qc.CloseWithError(0, "open stream failed")
		_ = tr.Close()
		_ = udp.Close()
		return nil, fmt.Errorf("session: forward open stream: %w", err)
	}
	return &ForwardSession{
		conn:      &fwdQuicConn{conn: qc},
		stream:    &fwdQuicStream{s: st},
		transport: tr,
		udp:       udp,
	}, nil
}

// AcceptForward is the provider-side bring-up: opens the forward
// socket bound to the granted allocation, listens via quic.Transport,
// and accepts ONE peer connection + ONE stream. The caller bridges
// the returned stream to its local backend.
//
// AcceptForward intentionally accepts a single connection; the
// AllocGranted is per-stream, so each forward session owns its own
// quic.Transport. Two concurrent streams between the same pair of
// agents end up on two independent UDP sockets — the relay treats
// them as independent allocations.
func AcceptForward(
	ctx context.Context,
	granted *orpv1.AllocGranted,
	tlsConf *tls.Config,
) (*ForwardSession, error) {
	if granted == nil || granted.MyAllocation == 0 || granted.PeerAllocation == 0 {
		return nil, errors.New("session: invalid AllocGranted")
	}
	relay, err := netip.ParseAddrPort(granted.ForwardEndpoint)
	if err != nil {
		return nil, fmt.Errorf("session: parse forward endpoint %q: %w", granted.ForwardEndpoint, err)
	}
	udp, err := forward.Dial(relay, granted.MyAllocation, granted.PeerAllocation)
	if err != nil {
		return nil, err
	}
	tr := &quic.Transport{Conn: udp}

	tlsConf = ensureForwardALPN(tlsConf)
	ln, err := tr.Listen(tlsConf, defaultQUICConfig())
	if err != nil {
		_ = tr.Close()
		_ = udp.Close()
		return nil, fmt.Errorf("session: forward listen: %w", err)
	}
	defer func() { _ = ln.Close() }()

	qc, err := ln.Accept(ctx)
	if err != nil {
		_ = tr.Close()
		_ = udp.Close()
		return nil, fmt.Errorf("session: forward accept conn: %w", err)
	}
	st, err := qc.AcceptStream(ctx)
	if err != nil {
		_ = qc.CloseWithError(0, "accept stream failed")
		_ = tr.Close()
		_ = udp.Close()
		return nil, fmt.Errorf("session: forward accept stream: %w", err)
	}
	return &ForwardSession{
		conn:      &fwdQuicConn{conn: qc},
		stream:    &fwdQuicStream{s: st},
		transport: tr,
		udp:       udp,
	}, nil
}

// ForwardALPN is the ALPN both sides of a forward-mode e2e QUIC
// connection negotiate. Distinct from the relay's ALPN so a
// misconfigured peer dialing the relay's port directly errors fast
// instead of half-handshaking.
const ForwardALPN = "outrelay-fwd/1"

func ensureForwardALPN(c *tls.Config) *tls.Config {
	cc := c.Clone()
	cc.NextProtos = []string{ForwardALPN}
	if cc.MinVersion == 0 {
		cc.MinVersion = tls.VersionTLS13
	}
	return cc
}

// defaultQUICConfig matches lib/transport's defaults closely enough
// for forward mode: idle timeout long enough that a brief stall on
// the relay doesn't tear connections down, no datagram support
// (forward path is stream-oriented), keepalive on so middleboxes
// holding the UDP-flow record don't expire it.
//
// HandshakeIdleTimeout is set explicitly because the dialer side
// can race the listener side's bring-up by a few ms to a few hundred
// ms — the listener has to walk through STREAM_ACCEPT, a stream-mode
// signal, and the AcceptForward bind sequence before it is ready to
// receive Initial packets. quic-go's default (5s) is fine on a quiet
// machine but flakes on contended CI runners with constrained UDP
// buffers, so we widen the window.
func defaultQUICConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout: 30_000_000_000, // 30s
		MaxIdleTimeout:       45_000_000_000, // 45s
		KeepAlivePeriod:      15_000_000_000, // 15s
	}
}

// Adapters — quic-go's Conn / Stream wrapped to satisfy lib/transport
// types. Mirrors lib/transport/quic.go's quicConn / quicStream but
// stays inside session/ to avoid pulling forward into lib/transport's
// import graph.

type fwdQuicConn struct {
	conn *quic.Conn
}

func (c *fwdQuicConn) OpenStream(ctx context.Context) (transport.Stream, error) {
	s, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return &fwdQuicStream{s: s}, nil
}

func (c *fwdQuicConn) AcceptStream(ctx context.Context) (transport.Stream, error) {
	s, err := c.conn.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return &fwdQuicStream{s: s}, nil
}

func (c *fwdQuicConn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *fwdQuicConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }
func (c *fwdQuicConn) TLS() tls.ConnectionState {
	return c.conn.ConnectionState().TLS
}
func (c *fwdQuicConn) Close() error { return c.conn.CloseWithError(0, "") }

type fwdQuicStream struct {
	s *quic.Stream
}

func (s *fwdQuicStream) Read(p []byte) (int, error)  { return s.s.Read(p) }
func (s *fwdQuicStream) Write(p []byte) (int, error) { return s.s.Write(p) }
func (s *fwdQuicStream) Close() error                { return s.s.Close() }
func (s *fwdQuicStream) StreamID() uint64            { return uint64(s.s.StreamID()) } // #nosec G115 -- quic.StreamID is non-negative
func (s *fwdQuicStream) CancelRead(code uint64) {
	s.s.CancelRead(quic.StreamErrorCode(code))
}
func (s *fwdQuicStream) CloseWrite() error { return s.s.Close() }
