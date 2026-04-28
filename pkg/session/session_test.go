// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package session_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/boanlab/OutRelay/lib/identity"
	"github.com/boanlab/OutRelay/lib/orp"
	orpv1 "github.com/boanlab/OutRelay/lib/orp/v1"
	"github.com/boanlab/OutRelay/lib/transport"
	"github.com/boanlab/OutRelay/pkg/pki"

	"github.com/boanlab/outrelay-agent/pkg/session"
)

// TestSessionExposeAndIncoming exercises the agent's wire behavior
// against a stub relay implemented inline. The stub speaks just enough
// of the relay protocol to verify the agent's HELLO/REGISTER and
// INCOMING_STREAM dispatch paths.
func TestSessionExposeAndIncoming(t *testing.T) {
	t.Parallel()

	ca, err := pki.NewCA()
	if err != nil {
		t.Fatal(err)
	}
	relayName, _ := identity.NewAgent("acme")
	agentName, _ := identity.NewAgent("acme")

	relayCert := issueCert(t, ca, relayName)
	agentCert := issueCert(t, ca, agentName)

	relayTLS := &tls.Config{
		Certificates: []tls.Certificate{*relayCert},
		ClientCAs:    ca.CertPool(),
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
	ln, err := transport.ListenQUIC("127.0.0.1:0", relayTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	stub := newStubRelay()
	go stub.Run(t.Context(), t, ln)

	agentTLS := &tls.Config{
		Certificates: []tls.Certificate{*agentCert},
		RootCAs:      ca.CertPool(),
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS13,
	}

	sess, err := session.Dial(t.Context(), ln.Addr().String(), agentTLS, agentName.String(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("session.Dial: %v", err)
	}
	defer sess.Close()

	// The handler echoes incoming bytes back through a synthetic backend.
	if err := sess.Expose(t.Context(), "svc-echo", "127.0.0.1:0", func(_ context.Context, _ *orpv1.IncomingStream) (session.Backend, error) {
		return newEchoPipe(), nil
	}); err != nil {
		t.Fatalf("Expose: %v", err)
	}

	runCtx, runCancel := context.WithCancel(t.Context())
	defer runCancel()
	go func() { _ = sess.Run(runCtx) }()

	// Drive the stub relay to push an INCOMING_STREAM toward the agent
	// and exchange bytes over the spliced pair.
	got, err := stub.callService("svc-echo", []byte("ping"), 2*time.Second)
	if err != nil {
		t.Fatalf("stub call: %v", err)
	}
	if string(got) != "ping" {
		t.Fatalf("got %q, want %q", got, "ping")
	}
}

// stubRelay accepts a single agent connection, drives a HELLO/REGISTER
// exchange, and exposes a callService method that pushes an
// INCOMING_STREAM and reads bytes back. It is intentionally small —
// just enough wire behavior to prove the agent dispatches handlers
// correctly. Real relay logic lives in outrelay-relay/pkg/edge.
type stubRelay struct {
	mu        sync.Mutex
	agentConn transport.Conn
	ready     chan struct{}
}

func newStubRelay() *stubRelay {
	return &stubRelay{ready: make(chan struct{})}
}

func (r *stubRelay) Run(ctx context.Context, t *testing.T, ln transport.Listener) {
	t.Helper()

	conn, err := ln.Accept(ctx)
	if err != nil {
		return
	}

	// Read HELLO on the first stream and reply with HELLO_ACK.
	ctrl, err := conn.AcceptStream(ctx)
	if err != nil {
		return
	}
	hf, err := orp.ParseFrame(ctrl)
	if err != nil || hf.Type != orp.FrameTypeHello {
		return
	}
	hello := &orpv1.Hello{}
	if err := orp.UnmarshalProto(hf, orp.FrameTypeHello, hello); err != nil {
		return
	}
	if err := orp.WriteFrame(ctrl, orp.FrameTypeHelloAck, &orpv1.HelloAck{}); err != nil {
		return
	}

	// Expect a REGISTER and reply with REGISTER_ACK.
	rf, err := orp.ParseFrame(ctrl)
	if err != nil || rf.Type != orp.FrameTypeRegister {
		return
	}
	reg := &orpv1.Register{}
	if err := orp.UnmarshalProto(rf, orp.FrameTypeRegister, reg); err != nil {
		return
	}
	if err := orp.WriteFrame(ctrl, orp.FrameTypeRegisterAck, &orpv1.RegisterAck{
		ServiceId: reg.ServiceName,
	}); err != nil {
		return
	}

	r.mu.Lock()
	r.agentConn = conn
	r.mu.Unlock()
	close(r.ready)

	<-ctx.Done()
	_ = conn.Close()
}

// callService opens a fresh stream to the agent, sends INCOMING_STREAM,
// reads STREAM_ACCEPT, then writes payload and reads back len(payload)
// bytes within timeout.
func (r *stubRelay) callService(name string, payload []byte, timeout time.Duration) ([]byte, error) {
	select {
	case <-r.ready:
	case <-time.After(timeout):
		return nil, fmt.Errorf("stub: agent never connected")
	}

	r.mu.Lock()
	conn := r.agentConn
	r.mu.Unlock()

	s, err := conn.OpenStream(context.Background())
	if err != nil {
		return nil, err
	}
	defer s.Close()

	if err := orp.WriteFrame(s, orp.FrameTypeIncomingStream, &orpv1.IncomingStream{
		TargetService:  name,
		SourceAgentUri: "outrelay://acme/agent/test-stub",
	}); err != nil {
		return nil, err
	}
	ack, err := orp.ParseFrame(s)
	if err != nil {
		return nil, err
	}
	if ack.Type != orp.FrameTypeStreamAccept {
		return nil, fmt.Errorf("expected STREAM_ACCEPT, got %v", ack.Type)
	}

	if _, err := s.Write(payload); err != nil {
		return nil, err
	}

	buf := make([]byte, len(payload))
	if err := readWithTimeout(s, buf, timeout); err != nil {
		return nil, err
	}
	return buf, nil
}

// echoPipe is a synthetic in-memory Backend that echoes every byte
// written into it back to the reader. Used as a stand-in for a real
// local TCP backend in the agent unit test.
type echoPipe struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func newEchoPipe() *echoPipe {
	r, w := io.Pipe()
	return &echoPipe{r: r, w: w}
}

func (e *echoPipe) Read(p []byte) (int, error)  { return e.r.Read(p) }
func (e *echoPipe) Write(p []byte) (int, error) { return e.w.Write(p) }
func (e *echoPipe) Close() error {
	_ = e.r.Close()
	return e.w.Close()
}

func issueCert(t *testing.T, ca *pki.CA, name identity.Name) *tls.Certificate {
	t.Helper()
	csrDER, key, err := pki.NewCSR(name)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := ca.Sign(csrDER, name, 0)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: key, Leaf: leaf}
}

func readWithTimeout(r io.Reader, buf []byte, d time.Duration) error {
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(r, buf)
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(d):
		return context.DeadlineExceeded
	}
}
