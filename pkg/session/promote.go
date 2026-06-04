// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package session

import (
	"context"
	"errors"
	"fmt"
	"net"
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
				s.logger.Warn("session: CANDIDATE_ANSWER unmarshal failed", "err", err)
				continue
			}
			s.logger.Debug("session: CANDIDATE_ANSWER received",
				"stream_id", a.StreamId, "candidates", len(a.Candidates))
			s.deliverAnswer(a)
		case orp.FrameTypeCandidateOffer:
			o := &orpv1.CandidateOffer{}
			if err := orp.UnmarshalProto(f, orp.FrameTypeCandidateOffer, o); err != nil {
				s.logger.Warn("session: CANDIDATE_OFFER unmarshal failed", "err", err)
				continue
			}
			s.logger.Debug("session: CANDIDATE_OFFER received",
				"stream_id", o.StreamId, "candidates", len(o.Candidates))
			ans := s.AnswerOffer(o)
			s.logger.Debug("session: sending CANDIDATE_ANSWER",
				"stream_id", ans.StreamId, "candidates", len(ans.Candidates))
			if err := s.writeCtrl(orp.FrameTypeCandidateAnswer, ans); err != nil {
				s.logger.Warn("session: write CANDIDATE_ANSWER", "err", err)
			}
			// Responder-side warmup punch. By the time the initiator's
			// Engine.Check dials our srflx, our NAT must already have an
			// outbound conntrack entry whose reply tuple matches the
			// initiator's src — otherwise port-restricted NAT (e.g. Linux
			// MASQUERADE in CloudStack VR, AWS NAT GW) drops the inbound
			// as a NEW connection. Sending one byte to each peer
			// candidate from our SharedTransport socket pre-creates that
			// entry. No-op when running on DefaultDialer (no shared
			// socket, no NAT semantics to defeat).
			s.warmupPunch(o.StreamId, o.GetCandidates())
		case orp.FrameTypeStreamCheckpoint:
			cp := &orpv1.StreamCheckpoint{}
			if err := orp.UnmarshalProto(f, orp.FrameTypeStreamCheckpoint, cp); err != nil {
				s.logger.Warn("session: STREAM_CHECKPOINT unmarshal failed", "err", err)
				continue
			}
			s.applyCheckpoint(cp)
		case orp.FrameTypeAllocGranted:
			g := &orpv1.AllocGranted{}
			if err := orp.UnmarshalProto(f, orp.FrameTypeAllocGranted, g); err != nil {
				s.logger.Warn("session: ALLOC_GRANTED unmarshal failed", "err", err)
				continue
			}
			// Resume vs new-stream dispatch: an AllocGranted whose
			// stream_id is already tracked by a ResumableForwardStream
			// wrapper is the relay's response to our FORWARD_RESUME
			// after reconnect — feed it to PrepareResume rather than
			// to the new-stream mode waiter (which is no longer
			// waiting for this id). Run PrepareResume on its own
			// goroutine so the controlReader never blocks on the
			// tunnel rebuild + STREAM_RESUME exchange.
			if rfs := s.LookupForwardStream(g.StreamId); rfs != nil {
				s.logger.Info("session: forward resume granted by relay",
					"stream_id", g.StreamId, "my_alloc", g.MyAllocation,
					"peer_alloc", g.PeerAllocation, "endpoint", g.ForwardEndpoint)
				go func(rfs *ResumableForwardStream, g *orpv1.AllocGranted) {
					if err := rfs.PrepareResume(ctx, g); err != nil {
						s.logger.Warn("session: forward resume failed; abandoning wrapper",
							"stream_id", g.StreamId, "err", err)
						rfs.markAbandoned()
						s.ForgetForwardStream(g.StreamId)
					}
				}(rfs, g)
				continue
			}
			s.logger.Info("session: stream mode resolved by relay (forward)",
				"stream_id", g.StreamId, "my_alloc", g.MyAllocation,
				"peer_alloc", g.PeerAllocation, "endpoint", g.ForwardEndpoint)
			s.deliverMode(g.StreamId, streamModeNotice{granted: g})
		case orp.FrameTypeStreamReady:
			r := &orpv1.StreamReady{}
			if err := orp.UnmarshalProto(f, orp.FrameTypeStreamReady, r); err != nil {
				s.logger.Warn("session: STREAM_READY unmarshal failed", "err", err)
				continue
			}
			s.logger.Info("session: stream mode resolved by relay (splice)", "stream_id", r.StreamId)
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

// warmupPunch sends a one-byte UDP datagram to every peer candidate
// from this session's SharedTransport socket. The QUIC layer is
// bypassed — the peer's quic-go demuxer drops the malformed datagram.
// The sole effect is to register an outbound conntrack entry on this
// side's NAT keyed by (local_socket → peer_addr); the initiator's
// subsequent dial from a different src then matches the reply tuple
// of that entry and is delivered by NAT instead of being treated as a
// fresh inbound and dropped.
//
// No-op if the session is not using a SharedTransport (e.g. the agent
// was started without --p2p-listen, or fell back to TCP). Errors per
// candidate are logged at debug and otherwise ignored — a routing
// failure to one address must not block the others.
func (s *Session) warmupPunch(streamID uint64, cands []*orpv1.Candidate) {
	s.logger.Debug("session: warmup punch enter",
		"stream_id", streamID,
		"candidates_in", len(cands),
		"dialer_type", fmt.Sprintf("%T", s.dialer))

	st, ok := s.dialer.(*transport.SharedTransport)
	if !ok || st == nil {
		s.logger.Debug("session: warmup punch skipped: dialer is not *SharedTransport",
			"stream_id", streamID, "dialer_type", fmt.Sprintf("%T", s.dialer))
		return
	}
	for _, c := range cands {
		if c == nil {
			s.logger.Debug("session: warmup punch skip: nil candidate",
				"stream_id", streamID)
			continue
		}
		if c.Ip == "" || c.Port == 0 || c.Port > 0xFFFF {
			s.logger.Debug("session: warmup punch skip: invalid endpoint",
				"stream_id", streamID, "kind", c.Kind, "ip", c.Ip, "port", c.Port)
			continue
		}
		ip := net.ParseIP(c.Ip)
		if ip == nil {
			s.logger.Debug("session: warmup punch skip: unparseable IP",
				"stream_id", streamID, "ip", c.Ip)
			continue
		}
		addr := &net.UDPAddr{IP: ip, Port: int(c.Port)}
		if _, err := st.WriteTo([]byte{0x00}, addr); err != nil {
			s.logger.Debug("session: warmup punch failed",
				"stream_id", streamID, "kind", c.Kind,
				"addr", addr.String(), "err", err)
			continue
		}
		s.logger.Debug("session: warmup punch sent",
			"stream_id", streamID, "kind", c.Kind, "addr", addr.String())
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
	if ch == nil {
		s.logger.Warn("session: CANDIDATE_ANSWER without waiter",
			"stream_id", a.StreamId)
		return
	}
	select {
	case ch <- a:
	default:
		s.logger.Warn("session: answer drop (waiter full)",
			"stream_id", a.StreamId)
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
	s.logger.Debug("session: stream-mode waiter registered", "stream_id", streamID)
	return ch
}

// CancelStreamModeWaiter removes a registered waiter without
// delivering. Idempotent.
func (s *Session) CancelStreamModeWaiter(streamID uint64) {
	s.p2pMu.Lock()
	_, existed := s.pendingMode[streamID]
	delete(s.pendingMode, streamID)
	s.p2pMu.Unlock()
	if existed {
		s.logger.Debug("session: stream-mode waiter cancelled", "stream_id", streamID)
	}
}

func (s *Session) deliverMode(streamID uint64, n streamModeNotice) {
	s.p2pMu.Lock()
	ch := s.pendingMode[streamID]
	s.p2pMu.Unlock()
	mode := "splice"
	if n.granted != nil {
		mode = "forward"
	}
	if ch == nil {
		s.logger.Warn("session: stream-mode delivery dropped (no waiter)",
			"stream_id", streamID, "mode", mode)
		return
	}
	select {
	case ch <- n:
		s.logger.Debug("session: stream-mode delivered",
			"stream_id", streamID, "mode", mode)
	default:
		s.logger.Warn("session: stream-mode delivery dropped (waiter full)",
			"stream_id", streamID, "mode", mode)
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

	// Candidate selection priority:
	//   1. opts.Locals (explicit injection — tests use this)
	//   2. s.localCandidates (set by main.go's --p2p-listen block via
	//      SetLocalCandidates: srflx + host candidates at the listener
	//      port, plus optional --p2p-advertise override). This is the
	//      production path — bypassing it falls back to port=0 host
	//      candidates that the responder can't punch toward.
	//   3. candidate.HostCandidates(opts.HostPort) — bare-port fallback
	//      for tests / DefaultDialer mode where no listener exists.
	locals := opts.Locals
	if len(locals) == 0 {
		s.p2pMu.Lock()
		sessionLocals := append([]*orpv1.Candidate(nil), s.localCandidates...)
		s.p2pMu.Unlock()
		if len(sessionLocals) > 0 {
			locals = p2p.FromPB(sessionLocals)
		} else {
			locals = candidate.HostCandidates(opts.HostPort)
		}
	}

	s.logger.Debug("session: promote begin", "stream_id", streamID, "locals", len(locals))
	defer s.logger.Debug("session: promote end", "stream_id", streamID)

	pr := &p2p.Promoter{
		StreamID: streamID,
		Engine:   eng,
		Locals:   locals,
		Logger:   s.logger,
		SendOffer: func(o *orpv1.CandidateOffer) error {
			s.logger.Debug("session: send CANDIDATE_OFFER",
				"stream_id", o.StreamId, "candidates", len(o.Candidates))
			return s.writeCtrl(orp.FrameTypeCandidateOffer, o)
		},
		RecvAnswer: func(ctx context.Context) (*orpv1.CandidateAnswer, error) {
			s.logger.Debug("session: waiting for CANDIDATE_ANSWER", "stream_id", streamID)
			select {
			case a := <-answerCh:
				s.logger.Debug("session: CANDIDATE_ANSWER delivered",
					"stream_id", a.StreamId, "candidates", len(a.Candidates))
				return a, nil
			case <-ctx.Done():
				s.logger.Debug("session: promote ctx done",
					"stream_id", streamID, "err", ctx.Err())
				return nil, ctx.Err()
			}
		},
		SendMigrate: func(m *orpv1.MigrateToP2P) error {
			s.logger.Debug("session: send MIGRATE_TO_P2P", "stream_id", m.StreamId)
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
