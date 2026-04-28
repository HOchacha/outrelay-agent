// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

// Package p2p drives §3.19 connectivity checks against a candidate
// pair matrix. §3.19.4 — given local + peer candidates,
// attempt direct QUIC dial in priority order and return the first
// pair whose handshake completes within a per-pair timeout. The
// returned transport.Conn is the established direct connection;
// the caller (Stream Migrator, §3.19.5) drives MIGRATE_TO_P2P
// and swaps the in-flight ResumableStream's inner over to it.
package p2p

import (
	"context"
	"crypto/tls"
	"errors"
	"time"

	"github.com/boanlab/OutRelay/lib/transport"

	"github.com/boanlab/outrelay-agent/pkg/candidate"
)

// DefaultPerPairTimeout caps each individual dial attempt — an
// unreachable address shouldn't burn the entire check budget. The
// candidate list is short (host + srflx) so trying them all is cheap.
const DefaultPerPairTimeout = 500 * time.Millisecond

// ErrNoPair is returned when every (local, remote) pair failed.
var ErrNoPair = errors.New("p2p: no candidate pair succeeded")

// CheckResult is the outcome of a successful connectivity check.
type CheckResult struct {
	Local  candidate.Candidate
	Remote candidate.Candidate
	Conn   transport.Conn // established direct QUIC connection
	RTT    time.Duration  // dial wall-clock as a coarse RTT proxy
}

// Engine encapsulates the per-attempt configuration. Construct once,
// run Check per stream that's evaluating P2P promotion.
type Engine struct {
	tlsConf *tls.Config
	perPair time.Duration
}

// NewEngine returns an engine that uses tlsConf for outgoing direct
// connections. tlsConf must contain the agent's client cert + the CA
// pool so peer certs verify; ServerName should match the peer agent's
// URI host (the trust domain), or a permissive VerifyPeerCertificate
// may be supplied.
func NewEngine(tlsConf *tls.Config) *Engine {
	return &Engine{tlsConf: tlsConf, perPair: DefaultPerPairTimeout}
}

// SetPerPairTimeout overrides the default 500ms budget. Use for tests.
func (e *Engine) SetPerPairTimeout(d time.Duration) {
	if d > 0 {
		e.perPair = d
	}
}

// Check iterates remote candidates (sorted by descending priority)
// and dials each. Returns the first pair whose QUIC handshake
// completes inside perPair. ctx may shorten the total budget.
//
// On success the returned Conn is owned by the caller; the caller
// closes it when the stream migrates back to relay or terminates.
//
// locals is informational: the dialer does not bind to a specific
// local address before connecting, so RFC 8445-style pair iteration
// with explicit local bind is not implemented.
func (e *Engine) Check(ctx context.Context, locals, remotes []candidate.Candidate) (*CheckResult, error) {
	sorted := candidate.Sort(remotes)
	for _, r := range sorted {
		if !r.Addr.IsValid() {
			continue
		}
		dialCtx, cancel := context.WithTimeout(ctx, e.perPair)
		start := time.Now()
		conn, err := transport.DialQUIC(dialCtx, r.Addr.String(), e.tlsConf, nil)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		rtt := time.Since(start)
		var local candidate.Candidate
		if len(locals) > 0 {
			local = candidate.Sort(locals)[0]
		}
		return &CheckResult{
			Local:  local,
			Remote: r,
			Conn:   conn,
			RTT:    rtt,
		}, nil
	}
	return nil, ErrNoPair
}
