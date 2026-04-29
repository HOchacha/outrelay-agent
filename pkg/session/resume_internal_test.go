// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package session

import (
	"bytes"
	"errors"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/boanlab/OutRelay/lib/orp"
	orpv1 "github.com/boanlab/OutRelay/lib/orp/v1"
	"github.com/boanlab/OutRelay/lib/resume"
)

// TestCompleteResumeRetransmitsGap verifies the gap-retransmit
// step of stream resume: after the relay echoes the peer's
// STREAM_RESUME, the agent reads peer.peer_ack_position and writes
// ring-buffered bytes (peer.peer_ack, my.sent] back onto the new
// stream.
func TestCompleteResumeRetransmitsGap(t *testing.T) {
	t.Parallel()

	id := resume.StreamID(0xfeed)
	st := resume.NewState(id, 4096)
	payload := bytes.Repeat([]byte{0xab}, 100)
	st.OnWrite(payload) // SentPos=100, ring holds 100 bytes

	rs := &ResumableStream{state: st}
	peerEcho := mustEncodeFrame(t, orp.FrameTypeStreamResume, &orpv1.StreamResume{
		StreamId:        uint64(id),
		MyPosition:      99,
		PeerAckPosition: 30,
	})
	fake := &bidiStream{readBuf: bytes.NewBuffer(peerEcho)}

	if err := (&Session{}).completeResume(rs, fake); err != nil {
		t.Fatalf("completeResume: %v", err)
	}

	gotWrites := fake.writeBuf.Bytes()
	if len(gotWrites) != 70 {
		t.Fatalf("retransmit wrote %d bytes, want 70", len(gotWrites))
	}
	for i, b := range gotWrites {
		if b != 0xab {
			t.Fatalf("byte %d = %x want 0xab", i, b)
		}
	}
}

// TestCompleteResumeMismatchedStreamID guards against a hypothetical
// relay misroute — the echo must carry our id; otherwise we error
// instead of silently retransmitting against the wrong peer.
func TestCompleteResumeMismatchedStreamID(t *testing.T) {
	t.Parallel()
	rs := &ResumableStream{state: resume.NewState(0xaaaa, 4096)}
	peerEcho := mustEncodeFrame(t, orp.FrameTypeStreamResume, &orpv1.StreamResume{
		StreamId: 0xbbbb,
	})
	fake := &bidiStream{readBuf: bytes.NewBuffer(peerEcho)}
	if err := (&Session{}).completeResume(rs, fake); err == nil {
		t.Fatal("expected stream_id mismatch error")
	}
}

// TestCompleteResumeBeforeRing surfaces the irrecoverable case where
// the peer asks for bytes the ring has already evicted.
func TestCompleteResumeBeforeRing(t *testing.T) {
	t.Parallel()
	id := resume.StreamID(0x1)
	st := resume.NewState(id, 32)
	st.OnWrite(bytes.Repeat([]byte{0xcd}, 200))
	rs := &ResumableStream{state: st}

	peerEcho := mustEncodeFrame(t, orp.FrameTypeStreamResume, &orpv1.StreamResume{
		StreamId:        uint64(id),
		PeerAckPosition: 10,
	})
	fake := &bidiStream{readBuf: bytes.NewBuffer(peerEcho)}
	err := (&Session{}).completeResume(rs, fake)
	if err == nil || !errors.Is(err, resume.ErrBeforeRing) {
		t.Fatalf("err=%v want ErrBeforeRing", err)
	}
}

// bidiStream implements transport.Stream with a fixed read source and
// a writer-side bytes.Buffer for assertions.
type bidiStream struct {
	mu       sync.Mutex
	readBuf  *bytes.Buffer
	writeBuf bytes.Buffer
}

func (b *bidiStream) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.readBuf.Read(p)
}

func (b *bidiStream) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.writeBuf.Write(p)
}

func (b *bidiStream) Close() error        { return nil }
func (b *bidiStream) StreamID() uint64    { return 0 }
func (b *bidiStream) CancelRead(_ uint64) {}

// mustEncodeFrame marshals msg into ORP framing for test fixtures.
func mustEncodeFrame(t *testing.T, typ orp.FrameType, msg proto.Message) []byte {
	t.Helper()
	rec := &recordWriter{}
	if err := orp.WriteFrame(rec, typ, msg); err != nil {
		t.Fatal(err)
	}
	return rec.buf
}
