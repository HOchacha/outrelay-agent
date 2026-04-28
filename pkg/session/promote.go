// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package session

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/boanlab/OutRelay/lib/orp"
	orpv1 "github.com/boanlab/OutRelay/lib/orp/v1"
	"github.com/boanlab/OutRelay/lib/transport"

	"github.com/boanlab/outrelay-agent/pkg/candidate"
	"github.com/boanlab/outrelay-agent/pkg/p2p"
)

// EnableP2P starts the background control-stream reader so Session
// can dispatch §3.19 frames (CANDIDATE_OFFER / CANDIDATE_ANSWER /
// MIGRATE_TO_*) to per-stream-id waiters. Call AFTER Expose() but
// before any Promote() call. Idempotent on repeated calls.
//
// ctx scopes the reader's lifetime — passing the same ctx that
// drives Run() is the typical pattern.
func (s *Session) EnableP2P(ctx context.Context) {
	s.p2pMu.Lock()
	if s.pendingAnswers == nil {
		s.pendingAnswers = map[uint64]chan *orpv1.CandidateAnswer{}
	}
	s.p2pMu.Unlock()
	s.ctrlReaderOnce.Do(func() { go s.controlReader(ctx) })
}

// controlReader reads frames from the agent's control stream forever
// (until ctx cancels or the stream closes). Routes:
//   - CANDIDATE_ANSWER  -> pending Promoter waiter (Promote initiator)
//   - CANDIDATE_OFFER   -> auto-respond with our local candidates
//     (responder side, §3.19.4)
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
	DialTLS interface{} // *tls.Config — kept as any to avoid an import here
}

// Promote drives §3.19 promotion for rs against the agent's peer.
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

// MigrateToDirect is the §3.19 Stream Migrator: open a fresh stream
// on peerConn, write STREAM_RESUME so the peer agent's resume matcher
// pairs it, and SwapInner the ResumableStream's underlying transport
// over to the direct path. §3.19.5 step T5.
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
