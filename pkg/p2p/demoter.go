// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package p2p

import (
	"context"
	"errors"
	"io"
	"log/slog"
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

	// Logger is optional. nil disables logging.
	Logger *slog.Logger

	// StreamID is used in log fields. 0 if unknown.
	StreamID uint64
}

func (d *Demoter) log() *slog.Logger {
	if d.Logger == nil {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return d.Logger
}

// ErrDemoterMisconfigured guards against partially-wired Demoters.
var ErrDemoterMisconfigured = errors.New("p2p: Demoter missing required hook")

// Run blocks until the underlying P2P conn fails or ctx cancels.
// Liveness is checked by AcceptStream — once the peer drops, the
// QUIC layer signals an error here. New streams the peer opens are
// silently closed (the P2P channel uses one stream per app stream;
// we don't expect new ones during normal operation).
func (d *Demoter) Run(ctx context.Context) error {
	log := d.log()
	if d.Conn == nil || d.OnDegrade == nil {
		log.Warn("p2p: demoter misconfigured", "stream_id", d.StreamID)
		return ErrDemoterMisconfigured
	}
	for {
		st, err := d.Conn.AcceptStream(ctx)
		if err != nil {
			if ctx.Err() != nil {
				log.Debug("p2p: demoter ctx done",
					"stream_id", d.StreamID, "err", ctx.Err())
				return ctx.Err()
			}
			log.Info("p2p: demoting to relay",
				"stream_id", d.StreamID,
				"reason", string(DemoteReasonPeerClose), "err", err)
			d.OnDegrade(DemoteReasonPeerClose, err)
			return err
		}
		log.Debug("p2p: demoter discarding peer-opened stream",
			"stream_id", d.StreamID)
		_ = st.Close()
	}
}
