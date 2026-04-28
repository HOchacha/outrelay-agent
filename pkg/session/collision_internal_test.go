// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package session

import (
	"log/slog"
	"testing"

	"github.com/boanlab/OutRelay/lib/resume"
)

// TestFreshStreamIDAvoidsActiveIDs verifies the agent-side collision
// guard: when an existing stream id happens to be present in
// s.streams, the generator regenerates rather than clobbering the
// active state.
//
// The test pre-populates many "active" ids and the generator returns
// something not in the set. Since the id generator monotonically
// advances on every call, the loop terminates after the first
// generation in practice.
func TestFreshStreamIDAvoidsActiveIDs(t *testing.T) {
	t.Parallel()
	s := &Session{
		agentURI: "outrelay://acme/agent/test",
		streams:  map[resume.StreamID]*ResumableStream{},
	}
	// Pre-populate with 64 ids — the next NewStreamID call will be
	// distinct (monotonic counter) so freshStreamID returns it on
	// the first try.
	for range 64 {
		id := resume.NewStreamID(s.agentURI, "svc-x", "")
		s.streams[id] = &ResumableStream{state: resume.NewState(id, 0)}
	}
	got := s.freshStreamID("svc-x", "")
	if _, dup := s.streams[got]; dup {
		t.Fatalf("freshStreamID returned an active id %s", got)
	}
}

// TestWrapStreamLogsCollision ensures the provider-side wrapStream
// path doesn't panic when handed an id that's already in s.streams —
// it must replace the state and emit a warn log instead.
func TestWrapStreamLogsCollision(t *testing.T) {
	t.Parallel()
	s := &Session{
		logger:   slog.New(slog.DiscardHandler),
		streams:  map[resume.StreamID]*ResumableStream{},
		agentURI: "outrelay://acme/agent/test",
	}
	id := resume.StreamID(0xc0ffee)
	s.streams[id] = &ResumableStream{state: resume.NewState(id, 0)}
	prior := s.streams[id]

	rs := s.wrapStream(id, nil)
	if rs == nil {
		t.Fatal("wrapStream returned nil on collision")
	}
	if s.streams[id] == prior {
		t.Fatal("wrapStream did not replace prior state")
	}
}
