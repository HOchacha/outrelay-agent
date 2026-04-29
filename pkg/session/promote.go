// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/boanlab/OutRelay/lib/orp"
	orpv1 "github.com/boanlab/OutRelay/lib/orp/v1"
	"github.com/boanlab/OutRelay/lib/resume"
	"github.com/boanlab/OutRelay/lib/transport"

	"github.com/boanlab/outrelay-agent/pkg/candidate"
	"github.com/boanlab/outrelay-agent/pkg/p2p"
)

// EnableP2P starts the background control-stream reader so Session
// can dispatch P2P-promotion frames (CANDIDATE_OFFER /
// CANDIDATE_ANSWER / MIGRATE_TO_*) to per-stream-id waiters. Call
// AFTER Expose() but before any Promote() call. Idempotent on
// repeated calls.
//
// ctx scopes the reader's lifetime — passing the same ctx that
// drives Run() is the typical pattern.
func (s *Session) EnableP2P(ctx context.Context) {
	s.p2pMu.Lock()
	if s.pendingAnswers == nil {
		s.pendingAnswers = map[uint64]chan *orpv1.CandidateAnswer{}
	}
	if s.pendingMode == nil {
		s.pendingMode = map[uint64]chan streamModeNotice{}
	}
	already := s.p2pEnabled
	s.p2pEnabled = true
	s.p2pCtx = ctx
	s.p2pMu.Unlock()
	if !already {
		go s.controlReader(ctx)
	}
}

// restartControlReaderIfEnabled is called from Reconnect after the
// new ctrl stream is wired in. The old reader has by then exited
// (its ParseFrame on the closed ctrl errored); without this
// re-spawn, no goroutine reads from the new ctrl, and inbound
// P2P-promotion frames sit in the QUIC stream forever.
func (s *Session) restartControlReaderIfEnabled() {
	s.p2pMu.Lock()
	enabled := s.p2pEnabled
	ctx := s.p2pCtx
	s.p2pMu.Unlock()
	if !enabled || ctx == nil {
		return
	}
	go s.controlReader(ctx)
}

// controlReader reads frames from the agent's control stream forever
// (until ctx cancels or the stream closes). Routes:
//   - CANDIDATE_ANSWER  -> pending Promoter waiter (Promote initiator)
//   - CANDIDATE_OFFER   -> auto-respond with our local candidates
//     (responder side)
//   - STREAM_CHECKPOINT -> per-stream resume.State.OnCheckpointFromPeer
//   - other             -> drop with warn log
//
// MIGRATE_TO_P2P / MIGRATE_TO_RELAY dispatch is not handled here:
// the responder agent's listener-side accept path is wired by the
// caller (e.g. tests stand up their own listener).
func (s *Session) controlReader(ctx context.Context) {
	for {
		f, err := orp.ParseFrame(s.ctrl)
		if err != nil {
			if ctx.Err() == nil {
				s.logger.Warn("session: ctrl reader stopped", "err", err)
			}
			return
		}
		switch f.Type {
		case orp.FrameTypeCandidateAnswer:
			a := &orpv1.CandidateAnswer{}
			if err := orp.UnmarshalProto(f, orp.FrameTypeCandidateAnswer, a); err != nil {
				continue
			}
			s.deliverAnswer(a)
		case orp.FrameTypeCandidateOffer:
			o := &orpv1.CandidateOffer{}
			if err := orp.UnmarshalProto(f, orp.FrameTypeCandidateOffer, o); err != nil {
				continue
			}
			ans := s.AnswerOffer(o)
			if err := s.writeCtrl(orp.FrameTypeCandidateAnswer, ans); err != nil {
				s.logger.Warn("session: write CANDIDATE_ANSWER", "err", err)
			}
		case orp.FrameTypeStreamCheckpoint:
			cp := &orpv1.StreamCheckpoint{}
			if err := orp.UnmarshalProto(f, orp.FrameTypeStreamCheckpoint, cp); err != nil {
				continue
			}
			s.applyCheckpoint(cp)
		case orp.FrameTypeAllocGranted:
			g := &orpv1.AllocGranted{}
			if err := orp.UnmarshalProto(f, orp.FrameTypeAllocGranted, g); err != nil {
				continue
			}
			s.deliverMode(g.StreamId, streamModeNotice{granted: g})
		case orp.FrameTypeStreamReady:
			r := &orpv1.StreamReady{}
			if err := orp.UnmarshalProto(f, orp.FrameTypeStreamReady, r); err != nil {
				continue
			}
			s.deliverMode(r.StreamId, streamModeNotice{}) // splice
		default:
			s.logger.Warn("session: unexpected ctrl frame", "type", f.Type)
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

// SetLocalCandidates registers the candidate set this session
// advertises in CANDIDATE_ANSWER replies (responder side). Replaces
// any prior set. Producer-side candidates passed to Promote come
// through PromoteOptions.Locals; this is for the inverse direction.
func (s *Session) SetLocalCandidates(cs []*orpv1.Candidate) {
	s.p2pMu.Lock()
	s.localCandidates = append([]*orpv1.Candidate(nil), cs...)
	s.p2pMu.Unlock()
}

// AnswerOffer builds a CANDIDATE_ANSWER for the given OFFER using the
// session's registered local candidates. Auto-invoked by controlReader
// on inbound OFFER; exposed publicly so unit tests can drive the
// responder logic without a full QUIC stream setup.
func (s *Session) AnswerOffer(offer *orpv1.CandidateOffer) *orpv1.CandidateAnswer {
	s.p2pMu.Lock()
	cs := append([]*orpv1.Candidate(nil), s.localCandidates...)
	s.p2pMu.Unlock()
	return &orpv1.CandidateAnswer{
		StreamId:   offer.StreamId,
		Candidates: cs,
	}
}

// writeCtrl marshals msg into a Frame of typ and writes it onto the
// shared control stream under ctrlWriteMu.
func (s *Session) writeCtrl(typ orp.FrameType, msg proto.Message) error {
	s.ctrlWriteMu.Lock()
	defer s.ctrlWriteMu.Unlock()
	return orp.WriteFrame(s.ctrl, typ, msg)
}

func (s *Session) registerAnswerWaiter(streamID uint64) chan *orpv1.CandidateAnswer {
	ch := make(chan *orpv1.CandidateAnswer, 1)
	s.p2pMu.Lock()
	s.pendingAnswers[streamID] = ch
	s.p2pMu.Unlock()
	return ch
}

func (s *Session) deliverAnswer(a *orpv1.CandidateAnswer) {
	s.p2pMu.Lock()
	ch, ok := s.pendingAnswers[a.StreamId]
	if ok {
		delete(s.pendingAnswers, a.StreamId)
	}
	s.p2pMu.Unlock()
	if ch != nil {
		select {
		case ch <- a:
		default:
		}
	}
}

// streamModeNotice is what the controlReader delivers to a per-stream
// mode waiter. granted == nil means the relay signalled splice mode
// (FrameTypeStreamReady); granted != nil means the relay signalled
// FORWARD mode and supplied the alloc info on the agent's stream-0
// ctrl.
type streamModeNotice struct {
	granted *orpv1.AllocGranted
}

// RegisterStreamModeWaiter installs a one-shot channel for either
// StreamReady (splice) or AllocGranted (forward). The caller MUST
// register before the action that triggers the relay's response —
// for the consumer side that's BEFORE writing OPEN_STREAM, for the
// provider side BEFORE writing STREAM_ACCEPT — so the controlReader
// has a place to deliver the inbound frame.
//
// Returned channel is buffer-1 and will receive exactly once. Caller
// must read from it (with their own context for cancellation) and is
// responsible for invoking CancelStreamModeWaiter on a context-cancel
// path so the map entry doesn't leak.
func (s *Session) RegisterStreamModeWaiter(streamID uint64) chan streamModeNotice {
	ch := make(chan streamModeNotice, 1)
	s.p2pMu.Lock()
	if s.pendingMode == nil {
		s.pendingMode = map[uint64]chan streamModeNotice{}
	}
	s.pendingMode[streamID] = ch
	s.p2pMu.Unlock()
	return ch
}

// CancelStreamModeWaiter removes a registered waiter without
// delivering. Idempotent.
func (s *Session) CancelStreamModeWaiter(streamID uint64) {
	s.p2pMu.Lock()
	delete(s.pendingMode, streamID)
	s.p2pMu.Unlock()
}

func (s *Session) deliverMode(streamID uint64, n streamModeNotice) {
	s.p2pMu.Lock()
	ch := s.pendingMode[streamID]
	s.p2pMu.Unlock()
	if ch != nil {
		select {
		case ch <- n:
		default:
		}
	}
}

// WaitForStreamMode blocks for either AllocGranted (forward) or
// StreamReady (splice) for streamID. Returns the AllocGranted iff the
// relay chose FORWARD; nil means splice mode signalled by StreamReady
// or ctx fired before any signal. The caller must have called
// RegisterStreamModeWaiter(streamID) before triggering the relay
// response (writing OPEN_STREAM on the consumer side, STREAM_ACCEPT
// on the provider side); otherwise this call is racy and may miss
// the frame.
//
// EnableP2P must be active so the controlReader is alive.
func (s *Session) WaitForStreamMode(ctx context.Context, streamID uint64) *orpv1.AllocGranted {
	s.p2pMu.Lock()
	ch, ok := s.pendingMode[streamID]
	s.p2pMu.Unlock()
	if !ok {
		// Caller forgot to register; treat as splice (no-op).
		return nil
	}
	defer s.CancelStreamModeWaiter(streamID)
	select {
	case n := <-ch:
		return n.granted
	case <-ctx.Done():
		return nil
	}
}

// PromoteOptions parameterises Session.Promote.
type PromoteOptions struct {
	// HostPort is the local port whose host candidates we advertise
	// (typically the port the agent's P2P listener is bound to).
	// Zero is acceptable for tests that pass explicit Locals.
	HostPort uint16

	// Locals overrides candidate gathering — when non-nil, used as
	// the offer's candidate set verbatim. Tests use this to inject
	// a known reachable address.
	Locals []candidate.Candidate

	// DialTLS is the TLS config used to dial peer candidates during
	// the connectivity check. Must contain the agent's client cert
	// + the trust pool that validates peer leaf certs.
	DialTLS any // *tls.Config — kept as any to avoid an import here
}

// Promote drives the P2P-promotion handshake for rs against the
// agent's peer.
// EnableP2P must be running. The peer agent is expected to be
// running its own answer/listener side concurrently.
//
// On success the returned p2p.CheckResult holds the live direct
// transport.Conn; the caller invokes MigrateToDirect to move rs's
// inner over.
func (s *Session) Promote(ctx context.Context, rs *ResumableStream, eng *p2p.Engine, opts PromoteOptions) (*p2p.CheckResult, error) {
	if rs == nil || eng == nil {
		return nil, errors.New("session: nil rs or engine")
	}
	s.p2pMu.Lock()
	enabled := s.pendingAnswers != nil
	s.p2pMu.Unlock()
	if !enabled {
		return nil, errors.New("session: EnableP2P not called")
	}

	streamID := uint64(rs.state.ID)
	answerCh := s.registerAnswerWaiter(streamID)

	locals := opts.Locals
	if len(locals) == 0 {
		locals = candidate.HostCandidates(opts.HostPort)
	}

	pr := &p2p.Promoter{
		StreamID: streamID,
		Engine:   eng,
		Locals:   locals,
		SendOffer: func(o *orpv1.CandidateOffer) error {
			return s.writeCtrl(orp.FrameTypeCandidateOffer, o)
		},
		RecvAnswer: func(ctx context.Context) (*orpv1.CandidateAnswer, error) {
			select {
			case a := <-answerCh:
				return a, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
		SendMigrate: func(m *orpv1.MigrateToP2P) error {
			return s.writeCtrl(orp.FrameTypeMigrateToP2P, m)
		},
	}
	return pr.Run(ctx)
}

// QueryServerReflexive asks the relay to echo the agent's NAT-mapped
// src ip:port via OBSERVED_ADDR_QUERY / OBSERVED_ADDR_RESP. Returns
// a Candidate with kind="srflx" — the agent typically pairs the IP
// with its listener port to form an externally-reachable host
// candidate.
//
// MUST be called BEFORE EnableP2P. The background controlReader
// installed by EnableP2P consumes every frame on the ctrl stream
// and would intercept the OBSERVED_ADDR_RESP, never delivering it
// here. Calling after EnableP2P returns an error rather than racing.
func (s *Session) QueryServerReflexive(ctx context.Context, timeout time.Duration) (candidate.Candidate, error) {
	s.p2pMu.Lock()
	enabled := s.p2pEnabled
	s.p2pMu.Unlock()
	if enabled {
		return candidate.Candidate{}, errors.New("session: QueryServerReflexive must run before EnableP2P")
	}
	return candidate.QueryServerReflexive(ctx, s.ctrl, timeout)
}

// AcceptDirect is the responder-side counterpart to MigrateToDirect.
// It runs an accept loop on ln, expecting peers to dial in over the
// host candidates this Session advertises (via SetLocalCandidates).
// For each new stream, the first frame must be STREAM_RESUME whose
// stream_id maps to an active *ResumableStream in this Session; on
// match, the gap from the peer's ack position is retransmitted and
// the wrapper's inner is swapped over to the direct stream — the
// bridge() above keeps running, transparently.
//
// Streams that don't match a known id are dropped. Returns when ctx
// is cancelled or the listener errors.
func (s *Session) AcceptDirect(ctx context.Context, ln transport.Listener) error {
	for {
		c, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("session: accept direct: %w", err)
		}
		go s.acceptDirectStreams(ctx, c)
	}
}

func (s *Session) acceptDirectStreams(ctx context.Context, c transport.Conn) {
	for {
		st, err := c.AcceptStream(ctx)
		if err != nil {
			return
		}
		go s.handleDirectStream(st)
	}
}

func (s *Session) handleDirectStream(st transport.Stream) {
	f, err := orp.ParseFrame(st)
	if err != nil {
		s.logger.Warn("session: direct: read first frame", "err", err)
		_ = st.Close()
		return
	}
	if f.Type != orp.FrameTypeStreamResume {
		s.logger.Warn("session: direct: expected STREAM_RESUME", "got", f.Type)
		_ = st.Close()
		return
	}
	peer := &orpv1.StreamResume{}
	if err := orp.UnmarshalProto(f, orp.FrameTypeStreamResume, peer); err != nil {
		_ = st.Close()
		return
	}

	sid := resume.StreamID(peer.StreamId)
	s.mu.RLock()
	rs, ok := s.streams[sid]
	s.mu.RUnlock()
	if !ok {
		s.logger.Warn("session: direct: unknown stream id", "id", sid.String())
		_ = st.Close()
		return
	}

	// Retransmit anything the peer hasn't yet acknowledged from our
	// side, then swap the wrapper's inner. PeerAckPosition fits in
	// int64 (it's a byte counter, never negative).
	gap, err := rs.state.RetransmitFrom(int64(peer.PeerAckPosition)) // #nosec G115
	if err != nil {
		s.logger.Warn("session: direct: retransmit gap unavailable", "err", err)
		_ = st.Close()
		return
	}
	if len(gap) > 0 {
		if _, err := st.Write(gap); err != nil {
			s.logger.Warn("session: direct: retransmit write", "err", err)
			_ = st.Close()
			return
		}
	}
	rs.SwapInner(st)
	s.logger.Info("session: direct: migrated", "id", sid.String())
}

// MigrateToDirect moves an in-flight ResumableStream off the relay
// onto a direct peer-to-peer transport. It opens a fresh stream on
// peerConn, writes STREAM_RESUME so the peer agent's resume matcher
// pairs it, and SwapInners the ResumableStream's underlying
// transport over to the direct path.
//
// On error the original inner is left untouched so the caller can
// retry or fall back to relay-mediated I/O.
func (s *Session) MigrateToDirect(ctx context.Context, rs *ResumableStream, peerConn transport.Conn) error {
	if rs == nil || peerConn == nil {
		return errors.New("session: nil rs or peerConn")
	}
	st, err := peerConn.OpenStream(ctx)
	if err != nil {
		return fmt.Errorf("session: open direct stream: %w", err)
	}
	myPos, peerAck := rs.state.ResumePayload()
	if err := orp.WriteFrame(st, orp.FrameTypeStreamResume, &orpv1.StreamResume{
		StreamId:        uint64(rs.state.ID),
		MyPosition:      uint64(myPos),   // #nosec G115 -- byte count, never negative
		PeerAckPosition: uint64(peerAck), // #nosec G115 -- byte count, never negative
	}); err != nil {
		_ = st.Close()
		return fmt.Errorf("session: send STREAM_RESUME on direct: %w", err)
	}
	rs.SwapInner(st)
	return nil
}
