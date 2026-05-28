// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package p2p

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"

	orpv1 "github.com/boanlab/OutRelay/lib/orp/v1"

	"github.com/boanlab/outrelay-agent/pkg/candidate"
)

// Promoter drives one stream through the four-step promotion path:
// gather candidates, exchange OFFER/ANSWER via the relay, run a
// connectivity check, and on success send MIGRATE_TO_P2P. The
// orchestration is transport-agnostic: tests inject SendOffer /
// RecvAnswer / SendMigrate hooks and the production session wires
// those to the agent's control stream + a per-stream-id frame
// router.
type Promoter struct {
	StreamID uint64
	Engine   *Engine

	// Locals are the agent's own candidates; the offer carries them
	// to the peer and the connectivity check uses them as the local
	// half of each pair.
	Locals []candidate.Candidate

	// SendOffer is invoked once with the agent's CandidateOffer.
	SendOffer func(*orpv1.CandidateOffer) error

	// RecvAnswer blocks until the peer's CandidateAnswer arrives or
	// ctx is cancelled. Returns nil if the channel was closed.
	RecvAnswer func(ctx context.Context) (*orpv1.CandidateAnswer, error)

	// SendMigrate is invoked once after the connectivity check
	// succeeds. Failure to send is non-fatal; the relay's LRU just
	// misses the metadata.
	SendMigrate func(*orpv1.MigrateToP2P) error

	// Logger is optional. nil disables logging.
	Logger *slog.Logger
}

func (p *Promoter) log() *slog.Logger {
	if p.Logger == nil {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return p.Logger
}

// ErrPromoterMisconfigured guards against partially-wired Promoters.
var ErrPromoterMisconfigured = errors.New("p2p: Promoter missing required hook")

// Run executes the four-step promotion. Returns a CheckResult with
// the live direct Conn on success; on failure (no candidate pair
// worked, ctx cancelled, hook errored) the caller keeps the stream
// on the relay.
func (p *Promoter) Run(ctx context.Context) (*CheckResult, error) {
	log := p.log()
	if p.Engine == nil || p.SendOffer == nil || p.RecvAnswer == nil {
		log.Warn("p2p: promoter misconfigured", "stream_id", p.StreamID)
		return nil, ErrPromoterMisconfigured
	}

	// 1. Send our offer.
	offer := &orpv1.CandidateOffer{
		StreamId:   p.StreamID,
		Candidates: toPB(p.Locals),
	}
	log.Debug("p2p: sending offer", "stream_id", p.StreamID, "local_count", len(p.Locals))
	if err := p.SendOffer(offer); err != nil {
		log.Warn("p2p: send offer failed", "stream_id", p.StreamID, "err", err)
		return nil, fmt.Errorf("p2p: send offer: %w", err)
	}

	// 2. Wait for peer's answer.
	answer, err := p.RecvAnswer(ctx)
	if err != nil {
		log.Warn("p2p: recv answer failed", "stream_id", p.StreamID, "err", err)
		return nil, fmt.Errorf("p2p: recv answer: %w", err)
	}
	if answer == nil {
		log.Warn("p2p: peer answer missing", "stream_id", p.StreamID)
		return nil, errors.New("p2p: peer answer missing")
	}
	if answer.StreamId != p.StreamID {
		log.Warn("p2p: answer stream_id mismatch",
			"stream_id", p.StreamID, "got", answer.StreamId)
		return nil, fmt.Errorf("p2p: answer stream_id mismatch: got %d, want %d",
			answer.StreamId, p.StreamID)
	}
	log.Debug("p2p: answer received",
		"stream_id", p.StreamID, "remote_count", len(answer.Candidates))

	// 3. Connectivity check.
	remotes := FromPB(answer.Candidates)
	res, err := p.Engine.Check(ctx, p.Locals, remotes)
	if err != nil {
		log.Warn("p2p: connectivity check failed",
			"stream_id", p.StreamID, "local_count", len(p.Locals),
			"remote_count", len(remotes), "err", err)
		return nil, err
	}
	log.Info("p2p: promoted",
		"stream_id", p.StreamID,
		"local", res.Local.Addr.String(),
		"remote", res.Remote.Addr.String())

	// 4. Notify relay (best-effort — failure here is logged not
	// fatal; the data path is already direct).
	if p.SendMigrate != nil {
		if err := p.SendMigrate(&orpv1.MigrateToP2P{
			StreamId: p.StreamID,
			Selected: toPBOne(res.Remote),
		}); err != nil {
			log.Debug("p2p: send migrate failed (non-fatal)",
				"stream_id", p.StreamID, "err", err)
		}
	}
	return res, nil
}

// toPB converts a slice of agent-side Candidate to the wire form.
func toPB(cs []candidate.Candidate) []*orpv1.Candidate {
	out := make([]*orpv1.Candidate, 0, len(cs))
	for _, c := range cs {
		out = append(out, toPBOne(c))
	}
	return out
}

func toPBOne(c candidate.Candidate) *orpv1.Candidate {
	return &orpv1.Candidate{
		Kind:     c.Kind,
		Ip:       c.Addr.Addr().String(),
		Port:     uint32(c.Addr.Port()),
		Priority: c.Priority,
	}
}

// FromPB inverts toPB. Invalid addresses are dropped.
func FromPB(cs []*orpv1.Candidate) []candidate.Candidate {
	out := make([]candidate.Candidate, 0, len(cs))
	for _, c := range cs {
		ip, err := netip.ParseAddr(c.Ip)
		if err != nil {
			continue
		}
		out = append(out, candidate.Candidate{
			Kind: c.Kind,
			// proto carries port as uint32; real TCP/UDP ports fit in uint16.
			Addr:     netip.AddrPortFrom(ip, uint16(c.Port)), // #nosec G115
			Priority: c.Priority,
		})
	}
	return out
}
