// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package session

// Unit tests for ResumableForwardStream + Session forwardStreams map.
// Internal package so tests poke at unexported fields directly. Full
// PrepareResume + tunnel STREAM_RESUME exchange ships under Stage 10
// (integration test with a real forward plane).

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/boanlab/OutRelay/lib/resume"
)

// fakeStream wraps a net.Conn for tests that need a real transport.Stream
// surface (Read / Write / Close / CloseWrite).
type fakeStream struct {
	net.Conn
	id uint64
}

func (s *fakeStream) StreamID() uint64  { return s.id }
func (s *fakeStream) CancelRead(uint64) {}
func (s *fakeStream) CloseWrite() error { return s.Close() }

// pipePair returns two halves of net.Pipe wrapped as fakeStream.
func pipePair(t *testing.T) (*fakeStream, *fakeStream) {
	t.Helper()
	a, b := net.Pipe()
	return &fakeStream{Conn: a, id: 1}, &fakeStream{Conn: b, id: 2}
}

func TestForwardStreamsRegisterLookupForget(t *testing.T) {
	t.Parallel()
	s := &Session{}
	rfs := &ResumableForwardStream{streamID: 42}

	if got := s.LookupForwardStream(42); got != nil {
		t.Fatalf("pre-register lookup: got %v, want nil", got)
	}
	s.RegisterForwardStream(42, rfs)
	if got := s.LookupForwardStream(42); got != rfs {
		t.Fatalf("post-register lookup: got %v, want %p", got, rfs)
	}
	if list := s.ActiveForwardStreams(); len(list) != 1 {
		t.Fatalf("active: got len=%d, want 1", len(list))
	}
	s.ForgetForwardStream(42)
	if got := s.LookupForwardStream(42); got != nil {
		t.Fatalf("post-forget lookup: got %v, want nil", got)
	}
}

// TestResumableForwardStreamReadWriteDelegates — Read / Write succeed
// when inner is healthy and bump the state counters used by
// FORWARD_RESUME.
func TestResumableForwardStreamReadWriteDelegates(t *testing.T) {
	t.Parallel()
	a, b := pipePair(t)
	defer func() {
		_ = a.Close()
		_ = b.Close()
	}()

	r := &ResumableForwardStream{
		inner:       a,
		state:       resume.NewState(resume.StreamID(1), 0),
		streamID:    1,
		resumeReady: make(chan struct{}),
	}

	// Drive a write on r, drain on b.
	payload := []byte("hello forward")
	writeErr := make(chan error, 1)
	go func() {
		_, err := r.Write(payload)
		writeErr <- err
	}()

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(b, got); err != nil {
		t.Fatalf("drain on b: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("payload: got %q, want %q", got, payload)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("r.Write: %v", err)
	}

	myPos, _ := r.state.ResumePayload()
	if myPos != int64(len(payload)) {
		t.Fatalf("state.my_position: got %d, want %d", myPos, len(payload))
	}
}

// TestResumableForwardStreamMarkAbandonedWakesReaders — markAbandoned
// closes resumeReady so a parked Read returns ErrStreamLost instead of
// hanging forever.
func TestResumableForwardStreamMarkAbandonedWakesReaders(t *testing.T) {
	t.Parallel()
	a, _ := pipePair(t)
	defer func() { _ = a.Close() }()

	// inner is set, but no goroutine ever writes to it, so the first
	// Read would block until either data arrives or the wrapper is
	// abandoned. We trigger abandon and verify ErrStreamLost.
	r := &ResumableForwardStream{
		inner:       a,
		state:       resume.NewState(resume.StreamID(1), 0),
		streamID:    1,
		resumeReady: make(chan struct{}),
	}

	// Pre-fail the underlying stream so r.Read parks on waitForResume
	// rather than blocking inside inner.Read.
	_ = a.SetReadDeadline(time.Now().Add(50 * time.Millisecond))

	var wg sync.WaitGroup
	wg.Add(1)
	var readErr error
	go func() {
		defer wg.Done()
		buf := make([]byte, 16)
		_, readErr = r.Read(buf)
	}()

	// Let the goroutine park, then mark abandoned.
	time.Sleep(150 * time.Millisecond)
	r.markAbandoned()
	wg.Wait()

	if !errors.Is(readErr, ErrStreamLost) {
		t.Fatalf("read after abandon: got %v, want ErrStreamLost", readErr)
	}
}

// TestSwapInnerWakesParked — SwapInner replaces inner and wakes a
// parked Read with the new stream. The new stream supplies fresh data.
func TestSwapInnerWakesParked(t *testing.T) {
	t.Parallel()
	dead1, _ := pipePair(t)
	new1, new1Peer := pipePair(t)
	defer func() {
		_ = dead1.Close()
		_ = new1.Close()
		_ = new1Peer.Close()
	}()

	r := &ResumableForwardStream{
		inner:       dead1,
		fs:          &ForwardSession{stream: dead1},
		state:       resume.NewState(resume.StreamID(1), 0),
		streamID:    1,
		resumeReady: make(chan struct{}),
	}
	// Wrap new1 in a sham ForwardSession (only Stream + Close are
	// touched by SwapInner). The test doesn't need a real conn or
	// transport — just the stream and a Close that doesn't panic.
	newFS := &ForwardSession{stream: new1}

	// Park a reader on the dead stream.
	_ = dead1.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	var wg sync.WaitGroup
	wg.Add(1)
	var got []byte
	var readErr error
	go func() {
		defer wg.Done()
		buf := make([]byte, 16)
		var n int
		n, readErr = r.Read(buf)
		got = buf[:n]
	}()

	time.Sleep(150 * time.Millisecond)

	// Feed bytes into the new stream side and SwapInner.
	go func() {
		_, _ = new1Peer.Write([]byte("after-swap"))
	}()
	r.SwapInner(newFS)

	wg.Wait()
	if readErr != nil {
		t.Fatalf("read after swap: %v", readErr)
	}
	if string(got) != "after-swap" {
		t.Fatalf("got %q, want %q", got, "after-swap")
	}
}
