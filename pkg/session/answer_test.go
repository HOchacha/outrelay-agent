// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package session

// Internal test: AnswerOffer builds the responder reply from the
// session's registered candidates. We poke the unexported field
// directly to avoid spinning up a full QUIC session for what is
// purely a frame-construction helper.

import (
	"testing"

	orpv1 "github.com/boanlab/OutRelay/lib/orp/v1"
)

func TestAnswerOfferEchoesStreamID(t *testing.T) {
	t.Parallel()
	s := &Session{
		localCandidates: []*orpv1.Candidate{
			{Kind: "host", Ip: "127.0.0.1", Port: 30001, Priority: 70},
			{Kind: "srflx", Ip: "203.0.113.5", Port: 30002, Priority: 20},
		},
	}
	offer := &orpv1.CandidateOffer{
		StreamId: 0xdead,
		Candidates: []*orpv1.Candidate{
			{Kind: "host", Ip: "10.0.0.1", Port: 40001},
		},
	}
	ans := s.AnswerOffer(offer)
	if ans == nil {
		t.Fatal("nil answer")
	}
	if ans.StreamId != 0xdead {
		t.Fatalf("stream_id mismatch: got %d", ans.StreamId)
	}
	if len(ans.Candidates) != 2 {
		t.Fatalf("got %d candidates, want 2", len(ans.Candidates))
	}
	if ans.Candidates[0].Ip != "127.0.0.1" {
		t.Fatalf("candidate[0]=%+v", ans.Candidates[0])
	}
}

func TestAnswerOfferWithoutLocalsReturnsEmpty(t *testing.T) {
	t.Parallel()
	s := &Session{}
	ans := s.AnswerOffer(&orpv1.CandidateOffer{StreamId: 1})
	if ans.StreamId != 1 || len(ans.Candidates) != 0 {
		t.Fatalf("got %+v", ans)
	}
}

func TestSetLocalCandidatesIsIndependent(t *testing.T) {
	t.Parallel()
	s := &Session{}
	original := []*orpv1.Candidate{{Kind: "host", Ip: "1.1.1.1", Port: 1}}
	s.SetLocalCandidates(original)
	// Mutate the input slice — Session's internal copy must not
	// reflect it, otherwise concurrent updaters would corrupt
	// in-flight Answer frames.
	original[0] = &orpv1.Candidate{Kind: "different", Ip: "9.9.9.9"}
	got := s.AnswerOffer(&orpv1.CandidateOffer{StreamId: 1}).Candidates
	if len(got) != 1 || got[0].Ip != "1.1.1.1" {
		t.Fatalf("internal copy was not made: %+v", got)
	}
}
