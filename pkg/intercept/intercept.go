// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

// Package intercept turns local application traffic into ORP service
// dials. Two modes are supported (§3.8):
//
// - explicit: agent listens on 127.0.0.1:<port> per service; the
// application dials the port directly.
// - tproxy:   linux iptables REDIRECT sends outgoing TCP to the
// agent's proxy port; SO_ORIGINAL_DST recovers the destination
// and a per-VIP map yields the service name. A small DNS server
// hands out the VIPs in the first place.
//
// Both modes implement the same Interceptor interface so the agent's
// glue layer is mode-agnostic.
package intercept

import (
	"context"
	"errors"
	"net"
)

// ErrClosed is returned by Accept after Close.
var ErrClosed = errors.New("intercept: closed")

// InterceptedConn is a hijacked outgoing application connection plus
// the resolved target service. The caller (agent's session glue) calls
// session.Dial against the relay with TargetSvc and bridges Local <->
// session stream until either side EOFs.
type InterceptedConn struct {
	Local     net.Conn
	OrigDest  net.Addr // for diagnostics; tproxy fills SO_ORIGINAL_DST
	TargetSvc string
}

// Interceptor accepts hijacked application connections and emits them
// as InterceptedConn events. Implementations are goroutine-safe; one
// goroutine usually loops on Accept.
type Interceptor interface {
	// Accept blocks until the next intercepted connection or ctx is
	// canceled. After Close it returns ErrClosed.
	Accept(ctx context.Context) (*InterceptedConn, error)

	// Close stops accepting new connections. In-flight conns returned
	// from earlier Accept calls are unaffected; the caller is
	// responsible for closing them.
	Close() error
}
