// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package session

// Internal tests for the Reconnect-side skip of forward-mode streams.
//
// Forward-mode streams carry application data over the relay's
// forward plane (an e2e QUIC tunnel between the two agents), not
// over the relay-mediated splice path. The ResumableStream wrapper
// the agent keeps for the relay-side data stream is then a liveness
// signal only — replaying STREAM_RESUME for it after a relay-side
// reconnect adds an entry to the relay's resume matcher that has
// no peer half to pair with, wasting matcher capacity and polluting
// debug output. The wrapper exposes MarkForward() so the bring-up
// code paths (DialForward / AcceptForward) can flag the wrapper;
// Reconnect's resume loop checks the flag and skips.
//
// These tests pin that behavior at the wrapper level. Full
// reconnect-loop integration is covered by the existing session
// reconnect tests.

import (
	"testing"

	"github.com/boanlab/OutRelay/lib/resume"
)

// TestMarkForwardSetsFlag — basic getter/setter contract.
func TestMarkForwardSetsFlag(t *testing.T) {
	t.Parallel()
	rs := &ResumableStream{
		state: resume.NewState(resume.StreamID(1), 0),
	}
	if rs.isForward() {
		t.Fatal("fresh ResumableStream should not be marked forward")
	}
	rs.MarkForward()
	if !rs.isForward() {
		t.Fatal("after MarkForward, isForward must be true")
	}
	// Idempotent — second call must not panic or flip state back.
	rs.MarkForward()
	if !rs.isForward() {
		t.Fatal("MarkForward must be idempotent")
	}
}

// TestMarkForwardConcurrentSafe — MarkForward and isForward are
// expected to be called from different goroutines (the dial path
// flags after AllocGranted; Reconnect reads during its resume loop).
// Race-detector run catches missing locks.
func TestMarkForwardConcurrentSafe(t *testing.T) {
	t.Parallel()
	rs := &ResumableStream{
		state: resume.NewState(resume.StreamID(1), 0),
	}
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			rs.MarkForward()
		}
		close(done)
	}()
	for i := 0; i < 1000; i++ {
		_ = rs.isForward()
	}
	<-done
	if !rs.isForward() {
		t.Fatal("forward flag should be set after concurrent MarkForward")
	}
}
