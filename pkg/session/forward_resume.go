// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package session

// ResumableForwardStream is the forward-mode counterpart of
// ResumableStream. It wraps the *application-facing* stream of an
// e2e QUIC tunnel that rides the relay's mini-TURN forward plane, and
// lets a relay-side reconnect drive a transparent rebuild of the
// entire tunnel (forward.Conn + e2e QUIC connection + stream) without
// the caller's bridge() seeing the break.
//
// Lifecycle:
//
//  1. main.go (or session.handleIncoming on the provider side) calls
//     WrapForward right after DialForward / AcceptForward succeeds.
//     The wrapper takes ownership of the ForwardSession and registers
//     itself on the Session's forwardStreams map.
//
//  2. bridge() reads/writes the wrapper. Counters in the embedded
//     resume.State track application-layer byte positions inside the
//     e2e tunnel — opaque to the relay.
//
//  3. On relay-side reconnect the Session's reconnect hook sends a
//     FORWARD_RESUME frame for each wrapper. The relay's
//     forwardMatcher pairs the two halves and writes a fresh
//     AllocGranted to each agent.
//
//  4. The agent's controlReader sees the AllocGranted, looks the
//     stream id up in forwardStreams, and calls PrepareResume on the
//     wrapper. PrepareResume tears down the old tunnel, dials or
//     accepts a fresh one with the granted allocs, exchanges a
//     tunnel-internal STREAM_RESUME with the peer for gap retransmit,
//     and SwapInners the wrapper's stream to the new one. The bridge
//     was parked by Read/Write on the dead stream and resumes from
//     SwapInner — transparent.
//
// Design rationale: hocha-work/forward-resume-flow.md §3.2.

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/boanlab/OutRelay/lib/orp"
	orpv1 "github.com/boanlab/OutRelay/lib/orp/v1"
	"github.com/boanlab/OutRelay/lib/resume"
	"github.com/boanlab/OutRelay/lib/transport"
)

// ForwardRole tags which side of a forward-mode tunnel a wrapper
// represents. On resume the role decides whether to call DialForward
// (initiator side, typically the consumer) or AcceptForward
// (responder side, typically the provider) to rebuild the tunnel.
type ForwardRole int

const (
	// ForwardRoleInitiator dialed its peer over the forward plane
	// during initial bring-up. On resume it dials again.
	ForwardRoleInitiator ForwardRole = iota
	// ForwardRoleResponder accepted from its peer during initial
	// bring-up. On resume it accepts again.
	ForwardRoleResponder
)

// ResumableForwardStream is the wrapper bridge() actually holds for
// forward-mode streams.
type ResumableForwardStream struct {
	mu sync.RWMutex

	// inner is the current e2e QUIC stream. Replaced atomically with
	// fs on PrepareResume via SwapInner.
	inner transport.Stream

	// fs owns the underlying ForwardSession (forward.Conn + quic.Transport
	// + e2e QUIC conn + stream). Replaced together with inner on resume.
	fs *ForwardSession

	state    *resume.State
	streamID uint64
	role     ForwardRole

	// peerTLS is what DialForward / AcceptForward needs to rebuild
	// the tunnel. For the initiator it's the peer-client TLS
	// (configured with the agent's client cert + CA); for the
	// responder it's the server TLS (mTLS server with the agent's
	// cert and a client CA pool).
	peerTLS *tls.Config

	logger *slog.Logger
	owner  *Session

	// resumeReady is closed by SwapInner / markAbandoned to wake
	// parked Read / Write calls. Same generational pattern as
	// ResumableStream.
	resumeReady chan struct{}
	abandoned   bool

	// resumeLock serialises concurrent PrepareResume attempts (e.g.,
	// a second AllocGranted arriving while the first resume is still
	// in flight). The first attempt holds the lock for the entirety
	// of the rebuild; subsequent callers either see resume already
	// completed or wait for it.
	resumeLock sync.Mutex
}

// WrapForward installs a fresh ResumableForwardStream around fs and
// registers it on sess so the reconnect hook and controlReader can
// find it. The returned wrapper is the bridge target.
func WrapForward(
	sess *Session,
	streamID uint64,
	fs *ForwardSession,
	role ForwardRole,
	peerTLS *tls.Config,
	logger *slog.Logger,
) *ResumableForwardStream {
	if logger == nil {
		logger = slog.Default()
	}
	r := &ResumableForwardStream{
		inner:       fs.Stream(),
		fs:          fs,
		state:       resume.NewState(resume.StreamID(streamID), 0),
		streamID:    streamID,
		role:        role,
		peerTLS:     peerTLS,
		logger:      logger,
		owner:       sess,
		resumeReady: make(chan struct{}),
	}
	if sess != nil {
		sess.RegisterForwardStream(streamID, r)
	}
	return r
}

// StreamID returns the logical stream id this wrapper resumes under.
func (r *ResumableForwardStream) StreamID() uint64 { return r.streamID }

// State exposes the per-stream resume state used by Reconnect to read
// (my_position, peer_ack_position) for FORWARD_RESUME.
func (r *ResumableForwardStream) State() *resume.State { return r.state }

// Read delegates to the current inner; on transport error it parks
// until SwapInner (resume completes) or markAbandoned within
// ResumeRetryWindow. Mirrors ResumableStream.Read.
func (r *ResumableForwardStream) Read(p []byte) (int, error) {
	deadline := time.Now().Add(ResumeRetryWindow)
	for {
		r.mu.RLock()
		if r.abandoned {
			r.mu.RUnlock()
			return 0, ErrStreamLost
		}
		inner := r.inner
		ready := r.resumeReady
		r.mu.RUnlock()

		n, err := inner.Read(p)
		if n > 0 {
			r.state.OnRead(n)
			return n, err
		}
		if err == nil {
			return 0, nil
		}
		if errors.Is(err, io.EOF) {
			return 0, err
		}
		if !r.waitForResume(ready, deadline) {
			return 0, err
		}
	}
}

// Write delegates to the current inner; partial writes spool into
// resume.State as they go so a mid-write SwapInner can retransmit
// the unflushed remainder. Mirrors ResumableStream.Write.
func (r *ResumableForwardStream) Write(p []byte) (int, error) {
	deadline := time.Now().Add(ResumeRetryWindow)
	written := 0
	for written < len(p) {
		r.mu.RLock()
		if r.abandoned {
			r.mu.RUnlock()
			if written == 0 {
				return 0, ErrStreamLost
			}
			return written, ErrStreamLost
		}
		inner := r.inner
		ready := r.resumeReady
		r.mu.RUnlock()

		n, err := inner.Write(p[written:])
		if n > 0 {
			r.state.OnWrite(p[written : written+n])
			written += n
		}
		if written == len(p) {
			return written, nil
		}
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			return written, err
		}
		if !r.waitForResume(ready, deadline) {
			return written, err
		}
	}
	return written, nil
}

func (r *ResumableForwardStream) waitForResume(ready <-chan struct{}, deadline time.Time) bool {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return false
	}
	t := time.NewTimer(remaining)
	defer t.Stop()
	select {
	case <-ready:
		return true
	case <-t.C:
		return false
	}
}

// SwapInner atomically replaces the wrapper's inner stream (and the
// ForwardSession that owns it) with the new pair. Parked Read / Write
// goroutines wake on the next loop iteration. Closes the old
// ForwardSession so the old forward.Conn and e2e QUIC release their
// resources.
func (r *ResumableForwardStream) SwapInner(newFS *ForwardSession) {
	r.mu.Lock()
	oldFS := r.fs
	r.inner = newFS.Stream()
	r.fs = newFS
	oldReady := r.resumeReady
	r.resumeReady = make(chan struct{})
	r.mu.Unlock()
	if oldReady != nil {
		close(oldReady)
	}
	if oldFS != nil {
		_ = oldFS.Close()
	}
}

// markAbandoned signals Read / Write that no SwapInner is coming.
// Idempotent. The wrapper is removed from the Session's forwardStreams
// map by Close (or by the controlReader on a fatal resume failure).
func (r *ResumableForwardStream) markAbandoned() {
	r.mu.Lock()
	if !r.abandoned {
		r.abandoned = true
		if r.resumeReady != nil {
			close(r.resumeReady)
			r.resumeReady = nil
		}
	}
	r.mu.Unlock()
}

// Close marks the wrapper abandoned, closes the current
// ForwardSession, and removes the wrapper from the Session's
// forwardStreams map.
func (r *ResumableForwardStream) Close() error {
	if r.owner != nil {
		r.owner.ForgetForwardStream(r.streamID)
	}
	r.markAbandoned()
	r.mu.RLock()
	fs := r.fs
	r.mu.RUnlock()
	if fs == nil {
		return nil
	}
	return fs.Close()
}

// CloseWrite half-closes the inner stream's write side. Mirrors
// ResumableStream.CloseWrite; used by bridges that want to preserve a
// one-shot request/response round-trip.
func (r *ResumableForwardStream) CloseWrite() error {
	type cw interface{ CloseWrite() error }
	r.mu.RLock()
	inner := r.inner
	r.mu.RUnlock()
	if hc, ok := inner.(cw); ok {
		return hc.CloseWrite()
	}
	return inner.Close()
}

// PrepareResume tears the current ForwardSession down and rebuilds it
// against the new AllocGranted, then exchanges a tunnel-internal
// STREAM_RESUME with the peer to recover any bytes neither side has
// ack'd. On success the wrapper's inner stream is swapped to the new
// tunnel and parked Read / Write callers proceed transparently.
//
// PrepareResume serialises through resumeLock so a second
// AllocGranted arriving mid-rebuild waits for the first to finish.
// Callers should run PrepareResume from a goroutine — the
// controlReader is single-threaded and must not block on this call.
func (r *ResumableForwardStream) PrepareResume(ctx context.Context, granted *orpv1.AllocGranted) error {
	r.resumeLock.Lock()
	defer r.resumeLock.Unlock()

	if granted == nil {
		return errors.New("session: nil AllocGranted on resume")
	}
	if granted.StreamId != r.streamID {
		return fmt.Errorf(
			"session: AllocGranted stream_id mismatch: got %d want %d",
			granted.StreamId, r.streamID,
		)
	}

	r.mu.RLock()
	abandoned := r.abandoned
	oldFS := r.fs
	r.mu.RUnlock()
	if abandoned {
		return errors.New("session: wrapper abandoned, cannot resume")
	}

	r.logger.Info("session: forward resume starting",
		"stream_id", r.streamID, "role", r.role,
		"my_alloc", granted.MyAllocation, "peer_alloc", granted.PeerAllocation,
		"endpoint", granted.ForwardEndpoint)

	// Close the dead tunnel first so its forward.Conn releases the
	// UDP socket (the WatchIdle background goroutine may already
	// have done this, but Close is idempotent).
	if oldFS != nil {
		_ = oldFS.Close()
	}

	// Rebuild based on role. Both calls produce a fresh ForwardSession
	// with a fresh e2e QUIC connection + first stream.
	var (
		newFS *ForwardSession
		err   error
	)
	switch r.role {
	case ForwardRoleInitiator:
		newFS, err = DialForward(ctx, granted, r.peerTLS, r.logger)
	case ForwardRoleResponder:
		newFS, err = AcceptForward(ctx, granted, r.peerTLS, r.logger)
	default:
		return fmt.Errorf("session: unknown forward role %v", r.role)
	}
	if err != nil {
		return fmt.Errorf("session: rebuild forward tunnel: %w", err)
	}

	// Tunnel-internal STREAM_RESUME exchange — same shape as
	// Session.Resume + Session.completeResume, but over the e2e QUIC
	// stream rather than a fresh relay-side stream.
	if err := r.exchangeTunnelResume(newFS.Stream()); err != nil {
		_ = newFS.Close()
		return fmt.Errorf("session: tunnel resume exchange: %w", err)
	}

	// All good — swap.
	r.SwapInner(newFS)
	r.logger.Info("session: forward resume swapped",
		"stream_id", r.streamID, "my_alloc", granted.MyAllocation)
	return nil
}

// exchangeTunnelResume runs the bidirectional STREAM_RESUME handshake
// on the new e2e stream. Both sides:
//  1. write their own STREAM_RESUME(stream_id, my_pos, peer_ack_pos)
//  2. read the peer's STREAM_RESUME
//  3. retransmit the (peer.peer_ack_position, my.my_position] range
//     from the local ring buffer so the peer's read pointer catches
//     up.
//
// The order matters: write first (small frame, fits in a single QUIC
// packet — no flow-control blocking) so the peer's read can complete
// even if we read before they write. After the handshake, the stream
// holds only application bytes from this point forward.
func (r *ResumableForwardStream) exchangeTunnelResume(st transport.Stream) error {
	myPos, peerAck := r.state.ResumePayload()
	if err := orp.WriteFrame(st, orp.FrameTypeStreamResume, &orpv1.StreamResume{
		StreamId:        r.streamID,
		MyPosition:      uint64(myPos),   // #nosec G115 -- byte count, never negative
		PeerAckPosition: uint64(peerAck), // #nosec G115 -- byte count, never negative
	}); err != nil {
		return fmt.Errorf("send STREAM_RESUME: %w", err)
	}

	f, err := orp.ParseFrame(st)
	if err != nil {
		return fmt.Errorf("read peer STREAM_RESUME: %w", err)
	}
	peer := &orpv1.StreamResume{}
	if err := orp.UnmarshalProto(f, orp.FrameTypeStreamResume, peer); err != nil {
		return err
	}
	if peer.StreamId != r.streamID {
		return fmt.Errorf(
			"peer STREAM_RESUME stream_id mismatch: got %d want %d",
			peer.StreamId, r.streamID,
		)
	}

	gap, err := r.state.RetransmitFrom(int64(peer.PeerAckPosition)) // #nosec G115
	if err != nil {
		return fmt.Errorf("retransmit gap unavailable: %w", err)
	}
	if len(gap) > 0 {
		if _, err := st.Write(gap); err != nil {
			return fmt.Errorf("retransmit write: %w", err)
		}
	}
	return nil
}
