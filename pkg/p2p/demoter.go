// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package p2p

import (
	"context"
	"errors"
	"time"

	"github.com/boanlab/OutRelay/lib/transport"
)

// DefaultIdleProbe is the period between liveness checks against an
// in-use P2P conn. The two demotion triggers we observe directly are
// explicit close (AcceptStream returns an error) and RTT timeout
// (QUIC's idle-timeout keepalive surfaces as an AcceptStream error
// once the peer has been unreachable for the negotiated window).
// Loss rate is not tracked.
const DefaultIdleProbe = 250 * time.Millisecond

// DemoteReason names what triggered demotion.
type DemoteReason string

const (
	DemoteReasonPeerClose  DemoteReason = "peer_close"
	DemoteReasonRTTTimeout DemoteReason = "rtt_timeout"
)

// Demoter watches a direct P2P conn for liveness failure. On the
// first error from AcceptStream / Close, OnDegrade is called once
// with a DemoteReason; the caller drives MIGRATE_TO_RELAY.
type Demoter struct {
	Conn      transport.Conn
	OnDegrade func(DemoteReason, error)
}

// ErrDemoterMisconfigured guards against partially-wired Demoters.
var ErrDemoterMisconfigured = errors.New("p2p: Demoter missing required hook")

// Run blocks until the underlying P2P conn fails or ctx cancels.
// Liveness is checked by AcceptStream — once the peer drops, the
// QUIC layer signals an error here. New streams the peer opens are
// silently closed (the P2P channel uses one stream per app stream;
// we don't expect new ones during normal operation).
func (d *Demoter) Run(ctx context.Context) error {
	if d.Conn == nil || d.OnDegrade == nil {
		return ErrDemoterMisconfigured
	}
	for {
		st, err := d.Conn.AcceptStream(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			d.OnDegrade(DemoteReasonPeerClose, err)
			return err
		}
		_ = st.Close()
	}
}
