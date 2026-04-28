// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package session

import (
	"sync"
	"testing"

	"github.com/boanlab/OutRelay/lib/orp"
	orpv1 "github.com/boanlab/OutRelay/lib/orp/v1"
	"github.com/boanlab/OutRelay/lib/resume"
)

// TestApplyCheckpointAdvancesPeerAck verifies an inbound
// STREAM_CHECKPOINT bumps PeerAckPos and frees ring space, which is
// the consumer half of — without this the ring grows monotonically
// until it evicts oldest bytes and resume becomes lossy.
func TestApplyCheckpointAdvancesPeerAck(t *testing.T) {
	t.Parallel()
	id := resume.StreamID(0xabcd)
	st := resume.NewState(id, 4096)
	// Fill 200 bytes into the ring as if Write had observed them.
	st.OnWrite(make([]byte, 200))

	rs := &ResumableStream{state: st}
	s := &Session{streams: map[resume.StreamID]*ResumableStream{id: rs}}
	s.applyCheckpoint(&orpv1.StreamCheckpoint{
		StreamId:        uint64(id),
		PeerAckPosition: 150,
	})

	if got := st.PeerAck(); got != 150 {
		t.Fatalf("PeerAck=%d want 150", got)
	}
	if got := st.Ring.Tail(); got != 150 {
		t.Fatalf("ring tail=%d want 150 (Discard should have freed pre-ack bytes)", got)
	}
}

// TestApplyCheckpointUnknownStreamID is a no-op — defensive against
// late checkpoints arriving for already-closed streams.
func TestApplyCheckpointUnknownStreamID(t *testing.T) {
	t.Parallel()
	s := &Session{streams: map[resume.StreamID]*ResumableStream{}}
	s.applyCheckpoint(&orpv1.StreamCheckpoint{StreamId: 0xdead, PeerAckPosition: 999})
	// No panic, no state change.
}

// TestEmitOnceWritesCheckpointForEachStream verifies the emitter
// writes one STREAM_CHECKPOINT frame per active stream carrying the
// correct positions. Captures bytes through a recordWriter that
// implements the io.Writer side of transport.Stream — the rest of the
// transport.Stream interface goes unused.
func TestEmitOnceWritesCheckpointForEachStream(t *testing.T) {
	t.Parallel()
	id := resume.StreamID(0x1234)
	st := resume.NewState(id, 4096)
	st.OnWrite(make([]byte, 64)) // SentPos=64
	st.OnRead(48)                // RecvPos=48

	rec := &recordWriter{}
	rs := &ResumableStream{state: st}
	s := &Session{
		ctrl:    rec,
		streams: map[resume.StreamID]*ResumableStream{id: rs},
	}
	s.emitOnce()

	frames := rec.parseFrames(t)
	if len(frames) != 1 {
		t.Fatalf("expected 1 frame, got %d", len(frames))
	}
	if frames[0].Type != orp.FrameTypeStreamCheckpoint {
		t.Fatalf("got frame type %v, want STREAM_CHECKPOINT", frames[0].Type)
	}
	cp := &orpv1.StreamCheckpoint{}
	if err := orp.UnmarshalProto(frames[0], orp.FrameTypeStreamCheckpoint, cp); err != nil {
		t.Fatal(err)
	}
	if cp.StreamId != uint64(id) || cp.MyPosition != 64 || cp.PeerAckPosition != 48 {
		t.Fatalf("payload mismatch: %+v", cp)
	}
}

// recordWriter is a minimal transport.Stream that just records bytes
// written. The emitter uses only the io.Writer side under
// ctrlWriteMu via orp.WriteFrame.
type recordWriter struct {
	mu  sync.Mutex
	buf []byte
}

func (r *recordWriter) Write(p []byte) (int, error) {
	r.mu.Lock()
	r.buf = append(r.buf, p...)
	r.mu.Unlock()
	return len(p), nil
}

// The remaining transport.Stream methods are unused by emitOnce but
// must be present to satisfy the interface.
func (r *recordWriter) Read(p []byte) (int, error) { return 0, nil }
func (r *recordWriter) Close() error               { return nil }
func (r *recordWriter) StreamID() uint64           { return 0 }

func (r *recordWriter) parseFrames(t *testing.T) []*orp.Frame {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []*orp.Frame{}
	rd := &readSlice{b: r.buf}
	for {
		f, err := orp.ParseFrame(rd)
		if err != nil {
			break
		}
		out = append(out, f)
	}
	return out
}

type readSlice struct {
	b   []byte
	off int
}

func (r *readSlice) Read(p []byte) (int, error) {
	if r.off >= len(r.b) {
		return 0, errEOF
	}
	n := copy(p, r.b[r.off:])
	r.off += n
	return n, nil
}

var errEOF = newErr("EOF")

type strErr string

func (s strErr) Error() string { return string(s) }
func newErr(s string) error    { return strErr(s) }
