// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package session

import (
	"context"
	"time"

	"github.com/boanlab/OutRelay/lib/orp"
	orpv1 "github.com/boanlab/OutRelay/lib/orp/v1"
	"github.com/boanlab/OutRelay/lib/resume"
)

// StartResume boots the stream-resume background loop:
// - inbound STREAM_CHECKPOINT frames are dispatched onto per-stream
// resume.State via OnCheckpointFromPeer (advances PeerAckPos and
// frees ring-buffer space)
// - outbound STREAM_CHECKPOINT frames are emitted every period (or
// resume.CheckpointPeriodMs ms when period <= 0) carrying
// (my_position=Sent, peer_ack_position=Received) for every active
// resumable stream
//
// ctx scopes the goroutines' lifetimes — pass the same ctx that drives
// Run(). Idempotent: a second call is a no-op.
func (s *Session) StartResume(ctx context.Context, period time.Duration) {
	if period <= 0 {
		period = time.Duration(resume.CheckpointPeriodMs) * time.Millisecond
	}
	// EnableP2P installs the same controlReader; sharing readers
	// across both entry points is fine — each call is idempotent on
	// the p2pEnabled flag, so at most one reader is alive at a time.
	s.EnableP2P(ctx)
	go s.emitCheckpoints(ctx, period)
}

func (s *Session) emitCheckpoints(ctx context.Context, period time.Duration) {
	t := time.NewTicker(period)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.emitOnce()
		}
	}
}

func (s *Session) emitOnce() {
	s.mu.RLock()
	states := make([]*resume.State, 0, len(s.streams))
	for _, rs := range s.streams {
		states = append(states, rs.state)
	}
	s.mu.RUnlock()
	for _, st := range states {
		// Byte counters are non-negative monotonics; uint64 is the wire type.
		cp := &orpv1.StreamCheckpoint{
			StreamId:        uint64(st.ID),
			MyPosition:      uint64(st.Sent()),     // #nosec G115 -- byte count, never negative
			PeerAckPosition: uint64(st.Received()), // #nosec G115 -- byte count, never negative
		}
		if err := s.writeCtrl(orp.FrameTypeStreamCheckpoint, cp); err != nil {
			// ctrl stream is broken — stop trying for this tick. The
			// next tick will retry, and Resume reconnect will rewire.
			return
		}
	}
}

// applyCheckpoint is called by controlReader on inbound
// STREAM_CHECKPOINT. We treat the peer's reported peer_ack_position
// as the upper bound of bytes we may discard from our local ring
// buffer.
func (s *Session) applyCheckpoint(cp *orpv1.StreamCheckpoint) {
	s.mu.RLock()
	rs, ok := s.streams[resume.StreamID(cp.StreamId)]
	s.mu.RUnlock()
	if !ok {
		return
	}
	rs.state.OnCheckpointFromPeer(int64(cp.PeerAckPosition)) // #nosec G115 -- byte count, fits in int64
}
