// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

// Package session manages an agent's outbound QUIC connection to the
// relay: HELLO handshake, REGISTER for exposed services, OPEN_STREAM
// for outgoing requests, and dispatch of INCOMING_STREAM requests
// from the relay to a per-service handler.
//
// On top of the base wire protocol the package implements:
//   - DialAny endpoint failover and RunWithReconnect orchestration,
//   - ResumableStream wrappers that survive a relay restart by
//     parking on SwapInner during transport errors, and
//   - Promote / MigrateToDirect for P2P promotion.
package session

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/boanlab/OutRelay/lib/orp"
	orpv1 "github.com/boanlab/OutRelay/lib/orp/v1"
	"github.com/boanlab/OutRelay/lib/resume"
	"github.com/boanlab/OutRelay/lib/transport"
)

// IncomingHandler is invoked when the relay sends INCOMING_STREAM to
// this agent. The handler decides accept vs reject, and on accept
// returns a stream-like ReadWriteCloser that will be spliced with the
// relay-side stream by the caller of Run().
//
// Implementation responsibility:
// - On accept, dial the local backend and return its conn.
// - On reject, return (nil, error) — Run will reply STREAM_REJECT.
type IncomingHandler func(ctx context.Context, in *orpv1.IncomingStream) (Backend, error)

// Backend is the local target of an INCOMING_STREAM (the agent's
// expose target — typically a net.Conn to 127.0.0.1:<port>).
type Backend interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Close() error
}

// Session holds the agent's QUIC connection to the relay, the control
// stream, and the per-service handler map.
type Session struct {
	conn     transport.Conn
	ctrl     transport.Stream
	logger   *slog.Logger
	agentURI string

	// ctrlWriteMu serializes writes onto ctrl so the foreground
	// (Expose / Resume / Promote / Migrate) and the background ctrl
	// reader (controlReader, started by EnableP2P) don't corrupt the
	// QUIC stream by interleaving frames.
	ctrlWriteMu sync.Mutex

	mu       sync.RWMutex
	handlers map[string]IncomingHandler
	streams  map[resume.StreamID]*ResumableStream // active resumable streams (wrappers, so Reconnect can SwapInner)

	// p2p* fields are populated by EnableP2P.
	p2pMu           sync.Mutex
	pendingAnswers  map[uint64]chan *orpv1.CandidateAnswer
	pendingMode     map[uint64]chan streamModeNotice
	localCandidates []*orpv1.Candidate
	// p2pEnabled is set true by the first EnableP2P call. It survives
	// across reconnects so RunWithReconnect knows to restart the
	// control-stream reader after each successful Reconnect — without
	// this, the original reader exits when the old ctrl stream errors
	// at relay restart, and CANDIDATE_ANSWER frames on the new ctrl
	// stream go unread (P2P promotions then time out forever).
	p2pEnabled bool

	// p2pCtx is the context passed to EnableP2P. Reconnect uses it to
	// spawn a fresh controlReader after swapping ctrl.
	p2pCtx context.Context

	// reconnecting is set by RunWithReconnect between detecting conn
	// loss and Reconnect completing. ResumableStream.Read/Write check
	// it: while true, they wait briefly on SwapInner before
	// propagating an inner error, so a relay restart looks like a
	// brief stall to the bridge instead of a stream tear-down. Outside
	// that window, errors propagate immediately (so an OPEN_STREAM
	// rejection doesn't stall the local conn for ResumeRetryWindow).
	reconnecting atomic.Bool

	// dialer is the Dialer used by Reconnect (and in principle any
	// future redial path). Dial / DialAny set it to DefaultDialer;
	// DialOnTransport sets it to a SharedTransport so the EIM
	// hole-punching path keeps the same UDP socket across reconnects.
	dialer transport.Dialer

	// forwardServerTLS, if non-nil, enables provider-side acceptance
	// of relay_mode=FORWARD streams: when handleIncoming sees an
	// AllocGranted (instead of StreamReady) on the agent's stream-0
	// ctrl after STREAM_ACCEPT, it opens a forward.Conn to the
	// granted endpoint and accepts a peer-initiated e2e QUIC
	// connection there, bridging that connection's first stream to
	// the registered backend instead of the relay-mediated stream.
	// Set via SetForwardServerTLS; nil means forward mode falls back
	// to the relay-mediated splice path (defensive — the relay only
	// sends AllocGranted when its own --listen-forward is enabled).
	forwardServerTLS *tls.Config

	// forwardStreamsMu protects forwardStreams independently of mu so
	// the controlReader's AllocGranted resume dispatch never contends
	// with the splice-stream registry.
	forwardStreamsMu sync.RWMutex
	// forwardStreams indexes active ResumableForwardStream wrappers by
	// stream_id. Populated by WrapForward, drained by ResumableForwardStream.Close.
	// Reconnect iterates this map to emit FORWARD_RESUME, and the
	// controlReader's AllocGranted handler looks up wrappers here to
	// distinguish a resume from a brand-new forward stream.
	forwardStreams map[uint64]*ResumableForwardStream
}

// SetForwardServerTLS enables provider-side acceptance of
// relay_mode=FORWARD streams over the relay's mini-TURN data plane.
// Pass the same mTLS server config used for P2P direct listening —
// the cert pool, client-cert requirement, and ALPN override applied
// internally guarantee both peers (consumer dialer + provider
// listener) speak the forward-mode ALPN over the e2e QUIC channel.
//
// Call before Run / RunWithReconnect so an inbound INCOMING_STREAM
// landing immediately after relay-side policy says FORWARD doesn't
// race the assignment.
func (s *Session) SetForwardServerTLS(c *tls.Config) {
	s.mu.Lock()
	s.forwardServerTLS = c
	s.mu.Unlock()
}

func (s *Session) forwardTLS() *tls.Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.forwardServerTLS
}

// RegisterForwardStream tracks a ResumableForwardStream wrapper so
// the Reconnect hook can iterate it for FORWARD_RESUME and the
// controlReader can route a subsequent AllocGranted to it on resume.
// Called by WrapForward; safe to call multiple times for the same id
// (later registration replaces earlier, mirroring re-bring-up).
func (s *Session) RegisterForwardStream(id uint64, rfs *ResumableForwardStream) {
	if rfs == nil {
		return
	}
	s.forwardStreamsMu.Lock()
	if s.forwardStreams == nil {
		s.forwardStreams = map[uint64]*ResumableForwardStream{}
	}
	s.forwardStreams[id] = rfs
	s.forwardStreamsMu.Unlock()
}

// ForgetForwardStream removes a wrapper from the tracking map. Called
// by ResumableForwardStream.Close and by the controlReader when a
// fatal resume failure abandons the wrapper. Idempotent.
func (s *Session) ForgetForwardStream(id uint64) {
	s.forwardStreamsMu.Lock()
	delete(s.forwardStreams, id)
	s.forwardStreamsMu.Unlock()
}

// LookupForwardStream returns the wrapper for id, or nil if no such
// wrapper is tracked. Used by the controlReader to distinguish
// "AllocGranted for an existing stream" (resume) from "AllocGranted
// for a brand-new stream" (initial bring-up).
func (s *Session) LookupForwardStream(id uint64) *ResumableForwardStream {
	s.forwardStreamsMu.RLock()
	defer s.forwardStreamsMu.RUnlock()
	return s.forwardStreams[id]
}

// ActiveForwardStreams snapshots the current set of wrappers, used by
// the Reconnect hook to send FORWARD_RESUME without holding the
// stream-tracking lock across the (potentially slow) ctrl writes.
func (s *Session) ActiveForwardStreams() []*ResumableForwardStream {
	s.forwardStreamsMu.RLock()
	defer s.forwardStreamsMu.RUnlock()
	out := make([]*ResumableForwardStream, 0, len(s.forwardStreams))
	for _, rfs := range s.forwardStreams {
		out = append(out, rfs)
	}
	return out
}

// DialAny tries each address in addrs in order and returns the first
// session that completes HELLO. The agent is configured with the LB
// endpoints of all relay replicas via --relay; if any one is healthy
// the agent connects.
func DialAny(ctx context.Context, addrs []string, tlsConf *tls.Config, agentURI string, logger *slog.Logger) (*Session, error) {
	if len(addrs) == 0 {
		return nil, errors.New("session: no relay addresses")
	}
	var firstErr error
	for _, addr := range addrs {
		s, err := Dial(ctx, addr, tlsConf, agentURI, logger)
		if err == nil {
			return s, nil
		}
		if firstErr == nil {
			firstErr = err
		}
		if logger != nil {
			logger.Warn("session: relay endpoint unhealthy", "addr", addr, "err", err)
		}
	}
	return nil, fmt.Errorf("session: all relay endpoints failed: %w", firstErr)
}

// DialAnyHappy is the "happy eyeballs" variant of DialAny: it dials
// every address concurrently and returns the first session that
// completes HELLO. Slower attempts are cancelled. Used to pick the
// lowest-RTT relay in multi-region deployments without an explicit
// RTT probe — the fastest dial-to-HELLO round-trip wins by
// construction. Sessions from losing dials are closed before the
// function returns so no resources leak.
//
// dialer is the same Dialer used inside Session (DefaultDialer for
// the standard QUIC path, SharedTransport for the P2P socket-reuse
// path, TCPDialer for the TCP/443 fallback). All N attempts share
// the dialer.
func DialAnyHappy(ctx context.Context, dialer transport.Dialer, addrs []string, tlsConf *tls.Config, agentURI string, logger *slog.Logger) (*Session, error) {
	if len(addrs) == 0 {
		return nil, errors.New("session: no relay addresses")
	}
	if len(addrs) == 1 {
		return DialWithDialer(ctx, dialer, addrs[0], tlsConf, agentURI, logger)
	}

	type attempt struct {
		s    *Session
		err  error
		addr string
	}
	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan attempt, len(addrs))
	for _, addr := range addrs {
		addr := addr
		go func() {
			s, err := DialWithDialer(raceCtx, dialer, addr, tlsConf, agentURI, logger)
			results <- attempt{s: s, err: err, addr: addr}
		}()
	}

	var (
		winner   *Session
		firstErr error
	)
	for i := 0; i < len(addrs); i++ {
		r := <-results
		switch {
		case r.err == nil && winner == nil:
			winner = r.s
			cancel() // race over — abort the slower attempts
			if logger != nil {
				logger.Info("session: nearest-relay selected", "addr", r.addr)
			}
		case r.err == nil && winner != nil:
			// Already had a winner; this one was just slower or
			// finished concurrently. Close it.
			_ = r.s.Close()
		case r.err != nil:
			if firstErr == nil {
				firstErr = r.err
			}
			if logger != nil && winner == nil {
				logger.Warn("session: relay endpoint unhealthy", "addr", r.addr, "err", r.err)
			}
		}
	}

	if winner != nil {
		return winner, nil
	}
	return nil, fmt.Errorf("session: all relay endpoints failed: %w", firstErr)
}

// Dial connects to the relay at addr, performs HELLO, and returns a
// ready Session. The caller's tls.Config must contain a client cert
// whose URI SAN matches agentURI.
func Dial(ctx context.Context, addr string, tlsConf *tls.Config, agentURI string, logger *slog.Logger) (*Session, error) {
	return DialWithDialer(ctx, transport.DefaultDialer{}, addr, tlsConf, agentURI, logger)
}

// DialWithDialer is like Dial but uses the supplied Dialer for the
// outbound QUIC connection (and stashes it on the Session so
// Reconnect uses the same transport on relay drops). Pass a
// *transport.SharedTransport to get EIM hole-punching semantics:
// the same UDP socket is used for the relay connection and (via
// the listener built from the same SharedTransport) inbound P2P.
func DialWithDialer(ctx context.Context, dialer transport.Dialer, addr string, tlsConf *tls.Config, agentURI string, logger *slog.Logger) (*Session, error) {
	if logger == nil {
		logger = slog.Default()
	}
	conn, err := dialer.Dial(ctx, addr, tlsConf, nil)
	if err != nil {
		return nil, err
	}
	ctrl, err := conn.OpenStream(ctx)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("session: open ctrl: %w", err)
	}
	if err := orp.WriteFrame(ctrl, orp.FrameTypeHello, &orpv1.Hello{
		ProtocolVersion: "orp/1",
		AgentUri:        agentURI,
	}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("session: send HELLO: %w", err)
	}
	f, err := orp.ParseFrame(ctrl)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("session: read HELLO_ACK: %w", err)
	}
	ack := &orpv1.HelloAck{}
	if err := orp.UnmarshalProto(f, orp.FrameTypeHelloAck, ack); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &Session{
		conn:     conn,
		ctrl:     ctrl,
		logger:   logger,
		agentURI: agentURI,
		handlers: map[string]IncomingHandler{},
		streams:  map[resume.StreamID]*ResumableStream{},
		dialer:   dialer,
	}, nil
}

// Close terminates the underlying QUIC connection.
func (s *Session) Close() error { return s.conn.Close() }

// Expose registers the service with the relay and binds h as the
// handler for INCOMING_STREAM frames on this service.
func (s *Session) Expose(ctx context.Context, name, localAddr string, h IncomingHandler) error {
	s.mu.Lock()
	s.handlers[name] = h
	s.mu.Unlock()

	if err := orp.WriteFrame(s.ctrl, orp.FrameTypeRegister, &orpv1.Register{
		ServiceName: name,
		LocalAddr:   localAddr,
	}); err != nil {
		return fmt.Errorf("session: send REGISTER: %w", err)
	}
	f, err := orp.ParseFrame(s.ctrl)
	if err != nil {
		return fmt.Errorf("session: read REGISTER_ACK: %w", err)
	}
	if f.Type != orp.FrameTypeRegisterAck {
		return fmt.Errorf("session: expected REGISTER_ACK, got %v", f.Type)
	}
	return nil
}

// Dial opens a stream toward target and writes OPEN_STREAM. The
// returned stream is wrapped with byte-position accounting so
// retransmission on relay failover stays consistent with the peer's
// view of how many bytes flowed each way (the stream-resume path).
//
// If the relay (or provider) rejects the stream, the rejection
// surfaces as a frame the caller will Read on the same stream.
//
// The relay always sends one of {StreamReady, AllocGranted} on the
// agent's stream-0 ctrl after policy resolution. To avoid a
// registration race, Dial installs the per-stream mode waiter
// BEFORE writing OPEN_STREAM. Callers consume the result with
// WaitForStreamMode(ctx, rs.StreamID()) and branch into forward
// (AllocGranted non-nil) or splice (nil) bridging.
func (s *Session) Dial(ctx context.Context, target, method string) (*ResumableStream, error) {
	st, err := s.conn.OpenStream(ctx)
	if err != nil {
		return nil, err
	}
	id := s.freshStreamID(target, method)
	// Install the mode waiter before sending OPEN_STREAM so a fast
	// relay can't deliver StreamReady / AllocGranted before we are
	// ready to receive it. Skipped when EnableP2P hasn't been called
	// — without a controlReader the wait would no-op anyway, and
	// callers that don't enable P2P / forward-mode want the minimal
	// splice path with no extra bookkeeping.
	s.p2pMu.Lock()
	ena := s.p2pEnabled
	s.p2pMu.Unlock()
	if ena {
		s.RegisterStreamModeWaiter(uint64(id))
	}
	if err := orp.WriteFrame(st, orp.FrameTypeOpenStream, &orpv1.OpenStream{
		TargetService: target,
		Method:        method,
		StreamId:      uint64(id),
	}); err != nil {
		if ena {
			s.CancelStreamModeWaiter(uint64(id))
		}
		_ = st.Close()
		return nil, fmt.Errorf("session: send OPEN_STREAM: %w", err)
	}
	return s.wrapStream(id, st), nil
}

// freshStreamID returns a StreamID that is not currently active in
// this Session. The id generator's monotonic counter + ns clock
// makes duplicates astronomically unlikely, but the local check
// costs nothing and prevents a wraparound from silently clobbering
// an active stream's resume state.
func (s *Session) freshStreamID(target, method string) resume.StreamID {
	for {
		id := resume.NewStreamID(s.agentURI, target, method)
		s.mu.RLock()
		_, dup := s.streams[id]
		s.mu.RUnlock()
		if !dup {
			return id
		}
	}
}

// wrapStream registers a fresh stream id and returns a ResumableStream
// that updates the per-stream byte counters on every read/write. On
// the consumer side the id comes from freshStreamID so duplicates
// can't happen; on the provider side the id is given by the peer's
// INCOMING_STREAM and a duplicate indicates either a peer bug or a
// rare collision — the prior state is replaced and a warn log is
// emitted, preferring to keep the new stream functional over
// preserving stale state.
func (s *Session) wrapStream(id resume.StreamID, inner transport.Stream) *ResumableStream {
	state := resume.NewState(id, 0) // 0 -> resume.DefaultRingCapacity
	rs := &ResumableStream{
		inner:       inner,
		state:       state,
		owner:       s,
		resumeReady: make(chan struct{}),
	}
	s.mu.Lock()
	if _, dup := s.streams[id]; dup {
		s.logger.Warn("session: stream id collision; replacing prior state", "id", id.String())
	}
	s.streams[id] = rs
	s.mu.Unlock()
	return rs
}

// forgetStream removes the stream from the active set and signals the
// wrapper so any parked Read / Write returns ErrStreamLost. Called by
// ResumableStream.Close and by Reconnect when a per-stream Resume
// fails past its retry window.
func (s *Session) forgetStream(id resume.StreamID) {
	s.mu.Lock()
	rs, ok := s.streams[id]
	delete(s.streams, id)
	s.mu.Unlock()
	if ok && rs != nil {
		rs.markAbandoned()
	}
}

// ResumeRetryWindow bounds how long Read / Write block waiting for
// SwapInner after the underlying stream errors with a transport-level
// failure (anything other than io.EOF). Sized to cover the worst-case
// asymmetric reconnect: when one side detects loss instantly via a
// QUIC ApplicationError but the other has to wait for MaxIdleTimeout,
// both bridges must still hold the stream open until BOTH sides have
// landed on the surviving relay and replayed STREAM_RESUME. Matches
// edge.ResumeWindow on the relay side.
const ResumeRetryWindow = 30 * time.Second

// ErrStreamLost is returned by Read / Write when the wrapper has been
// abandoned (Resume failed past the retry window or Close was called).
// Bridges treat this like io.EOF — tear down the local conn so the
// application reconnects at its own layer.
var ErrStreamLost = errors.New("session: stream lost")

// ResumableStream wraps a transport.Stream with byte counters and a
// ring buffer. Read/Write delegate to the inner stream and bump
// counters; State() exposes the per-stream State for tests / metrics.
//
// The inner stream is replaceable via SwapInner — that's the
// mechanism by which a stream-resume propagates the new stream to
// in-flight readers / writers without the application seeing the
// transition. When the inner errors, Read / Write block on a per-
// stream condvar until either SwapInner installs a new transport or
// the wrapper is abandoned, so a relay restart appears to the bridge
// as a brief stall instead of a stream tear-down.
type ResumableStream struct {
	mu    sync.RWMutex
	inner transport.Stream
	state *resume.State
	owner *Session

	// resumeReady is closed by SwapInner / abandon to wake parked
	// Read / Write calls. SwapInner installs a fresh chan in the
	// same critical section so subsequent waiters block on the new
	// generation rather than seeing an immediate close.
	resumeReady chan struct{}

	// abandoned is set when Resume failed past the retry window or
	// Close was called. Read / Write observe it and return
	// ErrStreamLost; bridges then exit cleanly.
	abandoned bool

	// forwardMode marks streams whose data is carried over an e2e QUIC
	// tunnel on the relay's forward plane rather than the relay-mediated
	// splice path. The relay-side stream this wrapper holds is then a
	// liveness signal only — replaying STREAM_RESUME on it after a
	// relay-side reconnect is useless (the relay has no matching peer
	// half to pair with) and pollutes the resume matcher with entries
	// that can never complete. Reconnect's Resume loop checks this flag
	// and skips. Phase 2 of forward-mode recovery (FORWARD_RESUME wire
	// + ResumableForwardStream wrapper) will replace this skip with
	// real transparent resume; for now it just keeps the wire and the
	// metrics clean.
	forwardMode bool
}

func (r *ResumableStream) Read(p []byte) (int, error) {
	deadline := time.Now().Add(ResumeRetryWindow)
	for {
		r.mu.RLock()
		if r.abandoned {
			r.mu.RUnlock()
			return 0, ErrStreamLost
		}
		inner := r.inner
		ready := r.resumeReady
		r.mu.RUnlock()

		n, err := inner.Read(p)
		if n > 0 {
			r.state.OnRead(n)
			return n, err
		}
		if err == nil {
			return 0, nil
		}
		// io.EOF is a clean peer close — no Resume can recover bytes
		// the peer already declared done. Anything else (idle timeout,
		// connection close, application error from a dead relay) is a
		// transport-level failure and may be recoverable via Reconnect
		// + SwapInner; park briefly to give that a chance.
		if errors.Is(err, io.EOF) {
			return 0, err
		}
		if !r.waitForResume(ready, deadline) {
			return 0, err
		}
	}
}

func (r *ResumableStream) Write(p []byte) (int, error) {
	deadline := time.Now().Add(ResumeRetryWindow)
	written := 0
	for written < len(p) {
		r.mu.RLock()
		if r.abandoned {
			r.mu.RUnlock()
			if written == 0 {
				return 0, ErrStreamLost
			}
			return written, ErrStreamLost
		}
		inner := r.inner
		ready := r.resumeReady
		r.mu.RUnlock()

		n, err := inner.Write(p[written:])
		if n > 0 {
			r.state.OnWrite(p[written : written+n])
			written += n
		}
		if written == len(p) {
			return written, nil
		}
		if err == nil {
			// Partial write without error is unusual — loop and
			// keep pushing.
			continue
		}
		if errors.Is(err, io.EOF) {
			return written, err
		}
		// Inner errored before draining p — wait for SwapInner so
		// the remainder lands on the new transport.
		if !r.waitForResume(ready, deadline) {
			return written, err
		}
	}
	return written, nil
}

// waitForResume blocks until ready closes (SwapInner / abandon) or
// deadline elapses. Returns true if the wait was woken by a signal
// (caller should re-read the latest inner) or false on timeout.
func (r *ResumableStream) waitForResume(ready <-chan struct{}, deadline time.Time) bool {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return false
	}
	t := time.NewTimer(remaining)
	defer t.Stop()
	select {
	case <-ready:
		return true
	case <-t.C:
		return false
	}
}

func (r *ResumableStream) Close() error {
	if r.owner != nil {
		r.owner.forgetStream(r.state.ID)
	}
	r.markAbandoned()
	r.mu.RLock()
	inner := r.inner
	r.mu.RUnlock()
	return inner.Close()
}

// MarkForward declares that this stream's data is carried over the
// relay's forward plane via an e2e QUIC tunnel, not via the
// relay-mediated splice path. The wrapper still tracks the relay-side
// stream as a liveness signal, but on Reconnect we skip STREAM_RESUME
// for it — there's no peer half on the relay's resume matcher to pair
// with, and the wrapper's bytes counters do not reflect application
// data anyway. Call once, right after the stream's mode is confirmed
// as FORWARD (AllocGranted received).
//
// Idempotent. Currently does not undo: a stream that has been marked
// forward stays marked for its lifetime. If FORWARD ever degrades
// back to relay-mediated splice in some future flow, this would need
// an explicit clear.
func (r *ResumableStream) MarkForward() {
	r.mu.Lock()
	r.forwardMode = true
	r.mu.Unlock()
}

// isForward reports whether MarkForward has been called.
func (r *ResumableStream) isForward() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.forwardMode
}

// markAbandoned signals to in-flight Read / Write that no further
// SwapInner is coming. Idempotent.
func (r *ResumableStream) markAbandoned() {
	r.mu.Lock()
	if !r.abandoned {
		r.abandoned = true
		if r.resumeReady != nil {
			close(r.resumeReady)
			r.resumeReady = nil
		}
	}
	r.mu.Unlock()
}

// SwapInner replaces the underlying stream and wakes any Read / Write
// calls that parked on a previous inner's error. Called by
// Session.Resume after a fresh STREAM_RESUME has been matched on the
// new relay, and by Session.MigrateToDirect / AcceptDirect after a
// P2P promotion completes.
//
// We CancelRead the previous inner so a Read currently parked
// waiting on it (a bridge expecting more bytes) returns an error,
// falls into waitForResume, observes resumeReady close, and
// resumes against the freshly installed inner. For the relay-
// resume case the previous inner is already broken so CancelRead
// is a no-op; for P2P migration it is what lets bytes actually
// start flowing over the direct path mid-stream.
func (r *ResumableStream) SwapInner(s transport.Stream) {
	r.mu.Lock()
	old := r.inner
	r.inner = s
	oldReady := r.resumeReady
	r.resumeReady = make(chan struct{})
	r.mu.Unlock()
	if oldReady != nil {
		close(oldReady)
	}
	if old != nil {
		old.CancelRead(0)
	}
}

// CloseWrite half-closes the write side of the inner stream so the
// peer learns no more data is coming, while leaving Read open until
// the peer's own FIN arrives. Required by bridges that want to
// preserve a one-shot request/response round-trip after the local
// app has finished writing.
func (r *ResumableStream) CloseWrite() error {
	type cw interface{ CloseWrite() error }
	r.mu.RLock()
	inner := r.inner
	r.mu.RUnlock()
	if hc, ok := inner.(cw); ok {
		return hc.CloseWrite()
	}
	return inner.Close()
}

// Resume opens a fresh stream on this session's connection, writes
// STREAM_RESUME with the given ResumableStream's current byte
// counters, reads the peer's STREAM_RESUME echo from the relay,
// retransmits the (peer.peer_ack, my.sent] byte range from the ring
// buffer, and finally swaps the wrapper's inner to the new stream so
// readers / writers transparently continue.
//
// The relay's matcher pairs this STREAM_RESUME with the peer's
// STREAM_RESUME by stream id; once matched, the relay echoes the
// peer's payload back on this stream and splices the rest.
//
// Returns resume.ErrBeforeRing if the peer's ack position has already
// been evicted from the ring — the stream is no longer resumable and
// the application must reconnect at the application layer.
func (s *Session) Resume(ctx context.Context, rs *ResumableStream) error {
	st, err := s.conn.OpenStream(ctx)
	if err != nil {
		return fmt.Errorf("session: open resume stream: %w", err)
	}
	myPos, peerAck := rs.state.ResumePayload()
	if err := orp.WriteFrame(st, orp.FrameTypeStreamResume, &orpv1.StreamResume{
		StreamId:        uint64(rs.state.ID),
		MyPosition:      uint64(myPos),   // #nosec G115 -- byte count, never negative
		PeerAckPosition: uint64(peerAck), // #nosec G115 -- byte count, never negative
	}); err != nil {
		_ = st.Close()
		return fmt.Errorf("session: send STREAM_RESUME: %w", err)
	}
	if err := s.completeResume(rs, st); err != nil {
		_ = st.Close()
		return err
	}
	rs.SwapInner(st)
	return nil
}

// completeResume reads the peer's echoed STREAM_RESUME and retransmits
// any bytes the peer hasn't yet acknowledged from this side's ring
// buffer. Shared by Session.Resume and the P2P direct migration
// path so retransmit semantics stay identical regardless of who
// carries the spliced bytes.
func (s *Session) completeResume(rs *ResumableStream, st transport.Stream) error {
	f, err := orp.ParseFrame(st)
	if err != nil {
		return fmt.Errorf("session: read peer STREAM_RESUME: %w", err)
	}
	peer := &orpv1.StreamResume{}
	if err := orp.UnmarshalProto(f, orp.FrameTypeStreamResume, peer); err != nil {
		return err
	}
	if peer.StreamId != uint64(rs.state.ID) {
		return fmt.Errorf("session: peer STREAM_RESUME stream_id mismatch: got %d want %d",
			peer.StreamId, uint64(rs.state.ID))
	}
	gap, err := rs.state.RetransmitFrom(int64(peer.PeerAckPosition)) // #nosec G115 -- byte count, fits in int64
	if err != nil {
		return fmt.Errorf("session: retransmit gap unavailable: %w", err)
	}
	if len(gap) > 0 {
		if _, err := st.Write(gap); err != nil {
			return fmt.Errorf("session: retransmit write: %w", err)
		}
	}
	return nil
}

// SwapConn replaces the underlying QUIC connection (used after a
// reconnect via DialAny). Subsequent Resume / Dial calls open
// streams on the new conn.
func (s *Session) SwapConn(conn transport.Conn) {
	s.conn = conn
}

// Reconnect tears down the dead QUIC conn, dials a fresh one against
// any of addrs, replays REGISTER for every previously exposed
// service, and replays STREAM_RESUME on every active ResumableStream
// — the relay's matcher pairs the halves and splice resumes from the
// peer-ack ring position.
//
// Streams whose Resume errors (e.g. ErrBeforeRing — peer's ack predates
// the ring tail) are forgotten; the application sees a Read/Write
// error and reconnects at its own layer. Other streams keep going.
func (s *Session) Reconnect(ctx context.Context, addrs []string, tlsConf *tls.Config) error {
	if len(addrs) == 0 {
		return errors.New("session: Reconnect requires at least one addr")
	}
	_ = s.conn.Close()

	var (
		conn    transport.Conn
		ctrl    transport.Stream
		dialErr error
	)
	dialer := s.dialer
	if dialer == nil {
		dialer = transport.DefaultDialer{}
	}
	for _, addr := range addrs {
		c, err := dialer.Dial(ctx, addr, tlsConf, nil)
		if err != nil {
			if dialErr == nil {
				dialErr = err
			}
			continue
		}
		ct, err := c.OpenStream(ctx)
		if err != nil {
			_ = c.Close()
			continue
		}
		if err := orp.WriteFrame(ct, orp.FrameTypeHello, &orpv1.Hello{
			ProtocolVersion: "orp/1",
			AgentUri:        s.agentURI,
		}); err != nil {
			_ = c.Close()
			continue
		}
		f, err := orp.ParseFrame(ct)
		if err != nil {
			_ = c.Close()
			continue
		}
		ack := &orpv1.HelloAck{}
		if err := orp.UnmarshalProto(f, orp.FrameTypeHelloAck, ack); err != nil {
			_ = c.Close()
			continue
		}
		conn, ctrl = c, ct
		break
	}
	if conn == nil {
		if dialErr == nil {
			dialErr = errors.New("session: all relay endpoints failed")
		}
		return dialErr
	}

	// Swap atomically against ctrlWriteMu so a concurrent emitter
	// goroutine can't write a half-frame across the boundary.
	s.ctrlWriteMu.Lock()
	s.conn = conn
	s.ctrl = ctrl
	s.ctrlWriteMu.Unlock()

	// Replay REGISTER for each previously exposed service. The ack is
	// drained here; we don't preserve service ids across reconnects.
	s.mu.RLock()
	exposed := make([]string, 0, len(s.handlers))
	for name := range s.handlers {
		exposed = append(exposed, name)
	}
	s.mu.RUnlock()
	for _, name := range exposed {
		if err := orp.WriteFrame(s.ctrl, orp.FrameTypeRegister, &orpv1.Register{ServiceName: name}); err != nil {
			return fmt.Errorf("session: re-register %q: %w", name, err)
		}
		f, err := orp.ParseFrame(s.ctrl)
		if err != nil {
			return fmt.Errorf("session: read REGISTER_ACK for %q: %w", name, err)
		}
		if f.Type != orp.FrameTypeRegisterAck {
			return fmt.Errorf("session: expected REGISTER_ACK for %q, got %v", name, f.Type)
		}
	}

	// Replay STREAM_RESUME for every active splice stream. Resume swaps
	// each wrapper's inner to the new transport in place, so bridge
	// goroutines transparently continue once the matcher pairs the
	// halves on the new relay.
	//
	// Forward-mode streams are skipped here — their relay-side stream
	// is a liveness signal only — and FORWARD_RESUME is sent instead
	// (see below) so the relay's forwardMatcher can re-pair the two
	// halves and re-emit AllocGranted with fresh allocations.
	streams := s.ActiveStreams()
	for _, rs := range streams {
		if rs.isForward() {
			s.logger.Debug("session: skipping STREAM_RESUME for forward-mode stream",
				"id", rs.state.ID.String())
			continue
		}
		if err := s.Resume(ctx, rs); err != nil {
			s.logger.Warn("session: resume stream failed; dropping",
				"id", rs.state.ID.String(), "err", err)
			s.forgetStream(rs.state.ID)
		}
	}

	// Replay FORWARD_RESUME for every active forward-mode stream so
	// the relay's forwardMatcher can re-pair the two halves and emit
	// a fresh AllocGranted to each agent. The controlReader then
	// routes the resume-shaped AllocGranted into
	// ResumableForwardStream.PrepareResume, which rebuilds the tunnel
	// and SwapInners — bridge goroutines continue transparently.
	// See hocha-work/forward-resume-flow.md.
	forwards := s.ActiveForwardStreams()
	for _, rfs := range forwards {
		myPos, peerAck := rfs.state.ResumePayload()
		if err := s.writeCtrl(orp.FrameTypeForwardResume, &orpv1.ForwardResume{
			StreamId:        rfs.streamID,
			MyPosition:      uint64(myPos),   // #nosec G115 -- byte count, never negative
			PeerAckPosition: uint64(peerAck), // #nosec G115 -- byte count, never negative
		}); err != nil {
			s.logger.Warn("session: send FORWARD_RESUME failed; abandoning wrapper",
				"stream_id", rfs.streamID, "err", err)
			rfs.markAbandoned()
			s.ForgetForwardStream(rfs.streamID)
			continue
		}
		s.logger.Debug("session: FORWARD_RESUME sent",
			"stream_id", rfs.streamID, "my_pos", myPos, "peer_ack_pos", peerAck)
	}
	return nil
}

// RunWithReconnect is Run wrapped in a reconnect loop. Each time the
// underlying QUIC conn drops, the session re-dials addrs, replays
// REGISTER + STREAM_RESUME, and resumes accepting incoming streams.
// Backoff doubles up to maxBackoff (30 s) between failed attempts.
//
// Returns nil on context cancellation, or the last reconnect error
// if every retry failed before ctx fired.
func (s *Session) RunWithReconnect(ctx context.Context, addrs []string, tlsConf *tls.Config) error {
	const maxBackoff = 30 * time.Second
	for {
		err := s.Run(ctx)
		if err == nil || errors.Is(err, context.Canceled) {
			return nil
		}
		s.logger.Warn("session: lost; reconnecting", "err", err)
		// Mark the recovery window so in-flight Read / Write calls on
		// active ResumableStreams park on SwapInner instead of failing
		// the bridge. Cleared once Reconnect returns (success or after
		// ctx fires).
		s.reconnecting.Store(true)
		backoff := time.Second
		attempt := 0
		for {
			attempt++
			s.logger.Debug("session: reconnect attempt",
				"attempt", attempt, "addrs", addrs, "backoff", backoff)
			rerr := s.Reconnect(ctx, addrs, tlsConf)
			if rerr == nil {
				s.logger.Info("session: reconnected", "attempt", attempt)
				// The old controlReader exited when the previous
				// ctrl stream errored. Restart it on the fresh ctrl
				// so P2P promotions keep working after a relay
				// restart.
				s.restartControlReaderIfEnabled()
				break
			}
			s.logger.Warn("session: reconnect attempt failed",
				"attempt", attempt, "err", rerr)
			select {
			case <-ctx.Done():
				s.logger.Info("session: reconnect abandoned (ctx done)",
					"attempt", attempt)
				s.reconnecting.Store(false)
				return nil
			case <-time.After(backoff):
			}
			if backoff < maxBackoff {
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
			}
		}
		s.reconnecting.Store(false)
	}
}

// ActiveStreams returns the currently registered ResumableStream
// wrappers — used by Reconnect to drive Resume across every active
// stream after the QUIC conn is swapped.
func (s *Session) ActiveStreams() []*ResumableStream {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*ResumableStream, 0, len(s.streams))
	for _, rs := range s.streams {
		out = append(out, rs)
	}
	return out
}

// State exposes the per-stream resume state (sent / received / peer-ack).
func (r *ResumableStream) State() *resume.State { return r.state }

// StreamID returns the stable id used in OPEN_STREAM and STREAM_RESUME.
func (r *ResumableStream) StreamID() resume.StreamID { return r.state.ID }

// Run blocks until the session ends, dispatching INCOMING_STREAM
// frames to registered handlers.
func (s *Session) Run(ctx context.Context) error {
	for {
		st, err := s.conn.AcceptStream(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return fmt.Errorf("session: accept: %w", err)
		}
		go s.handleIncoming(ctx, st)
	}
}

func (s *Session) handleIncoming(ctx context.Context, st transport.Stream) {
	f, err := orp.ParseFrame(st)
	if err != nil {
		_ = st.Close()
		return
	}
	if f.Type != orp.FrameTypeIncomingStream {
		s.logger.Warn("agent: expected INCOMING_STREAM", "got", f.Type)
		_ = st.Close()
		return
	}
	in := &orpv1.IncomingStream{}
	if err := orp.UnmarshalProto(f, orp.FrameTypeIncomingStream, in); err != nil {
		_ = st.Close()
		return
	}
	s.mu.RLock()
	h, ok := s.handlers[in.TargetService]
	s.mu.RUnlock()
	if !ok {
		_ = orp.WriteFrame(st, orp.FrameTypeStreamReject, &orpv1.StreamReject{
			Code: 404, Reason: "no handler",
		})
		_ = st.Close()
		return
	}
	backend, err := h(ctx, in)
	if err != nil {
		_ = orp.WriteFrame(st, orp.FrameTypeStreamReject, &orpv1.StreamReject{
			Code: 502, Reason: err.Error(),
		})
		_ = st.Close()
		return
	}
	// Install the mode waiter BEFORE writing STREAM_ACCEPT so the
	// relay's response (StreamReady or AllocGranted) can never land
	// on stream-0 before the controlReader has a route for it. Skip
	// when EnableP2P hasn't been called — without a controlReader
	// the wait would just block, and splice mode is the right
	// behaviour for stubs / minimal harnesses.
	s.p2pMu.Lock()
	ena := s.p2pEnabled
	s.p2pMu.Unlock()
	if ena {
		s.RegisterStreamModeWaiter(in.StreamId)
	}
	if err := orp.WriteFrame(st, orp.FrameTypeStreamAccept, &orpv1.StreamAccept{}); err != nil {
		if ena {
			s.CancelStreamModeWaiter(in.StreamId)
		}
		_ = backend.Close()
		_ = st.Close()
		return
	}

	// Provider side wraps the relay-side stream so it tracks the same
	// (sent, received) counters the consumer side does. The stream id
	// flows through INCOMING_STREAM so both ends agree.
	wrapped := s.wrapStream(resume.StreamID(in.StreamId), st)
	defer func() { _ = wrapped.Close() }()

	if ena {
		// 5s ceiling guards against a peer relay that never sends a
		// mode signal (older binary, mid-failover): falls back to
		// splice instead of hanging the stream open forever.
		modeCtx, modeCancel := context.WithTimeout(ctx, 5*time.Second)
		granted := s.WaitForStreamMode(modeCtx, in.StreamId)
		modeCancel()
		if granted != nil {
			ftls := s.forwardTLS()
			if ftls == nil {
				s.logger.Warn("agent: AllocGranted received but forward TLS not configured; falling back to relay-mediated bridge",
					"stream_id", in.StreamId)
				bridge(wrapped, backend)
				return
			}
			fs, err := AcceptForward(ctx, granted, ftls, s.logger)
			if err != nil {
				s.logger.Warn("agent: forward accept failed; tearing down stream",
					"stream_id", in.StreamId, "err", err)
				_ = backend.Close()
				return
			}
			// In forward mode the relay-mediated stream is just a
			// liveness signal. Bytes flow over fs.Stream() ↔ backend.
			// Tell the wrapper not to STREAM_RESUME the relay-side
			// stream on reconnect — there is no peer half to pair
			// with on the splice resume matcher.
			wrapped.MarkForward()
			// Wrap fs in a ResumableForwardStream so a relay
			// reconnect can drive PrepareResume (rebuild the tunnel
			// + tunnel-internal STREAM_RESUME) transparently under
			// the bridge. The wrapper takes ownership of fs and
			// closes it on its own Close.
			rfs := WrapForward(s, in.StreamId, fs,
				ForwardRoleResponder, ftls, s.logger)
			defer func() { _ = rfs.Close() }()
			bridge(rfs, backend)
			return
		}
	}
	bridge(wrapped, backend)
}

// bridge wires a <-> b in both directions and propagates a half-close
// on each direction's EOF. Without the half-close, a one-shot client
// (e.g. printf | nc) closes its write half right after the request
// and the bridge full-closes the local conn before the echo reply
// gets back through.
func bridge(a, b interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Close() error
}) {
	done := make(chan struct{}, 2)
	go func() { copyAndDone(a, b, done) }()
	go func() { copyAndDone(b, a, done) }()
	<-done
	<-done
	_ = a.Close()
	_ = b.Close()
}

// copyAndDone copies src -> dst and, on EOF, half-closes dst's write
// side so the peer sees end-of-stream without losing the read side.
func copyAndDone(dst, src interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
}, done chan<- struct{}) {
	defer func() { done <- struct{}{} }()
	buf := make([]byte, 64*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			type cw interface{ CloseWrite() error }
			if hc, ok := dst.(cw); ok {
				_ = hc.CloseWrite()
			}
			return
		}
	}
}
