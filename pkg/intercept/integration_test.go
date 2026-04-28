// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package intercept_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/boanlab/OutRelay/lib/identity"
	"github.com/boanlab/OutRelay/lib/orp"
	orpv1 "github.com/boanlab/OutRelay/lib/orp/v1"
	"github.com/boanlab/OutRelay/lib/transport"
	"github.com/boanlab/OutRelay/pkg/pki"

	"github.com/boanlab/outrelay-agent/pkg/intercept"
	"github.com/boanlab/outrelay-agent/pkg/session"
)

// TestExplicitInterceptToSession:
//
// An application dials the agent's localhost listener; bytes flow
// through the interceptor, into a session.Dial call, across a stub
// relay that synthesizes an INCOMING_STREAM at a second session, and
// back to a synthetic echo backend. The smallest e2e that exercises
// the explicit interceptor + session glue together.
func TestExplicitInterceptToSession(t *testing.T) {
	t.Parallel()

	ca, _ := pki.NewCA()
	relayName, _ := identity.NewAgent("acme")
	provName, _ := identity.NewAgent("acme")
	consName, _ := identity.NewAgent("acme")

	relayCert := issueCert(t, ca, relayName)
	provCert := issueCert(t, ca, provName)
	consCert := issueCert(t, ca, consName)

	// Stub relay listens with mTLS, accepts both agents, and pairs
	// streams with explicit "send INCOMING_STREAM to provider" logic.
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

	relayAddr := ln.Addr().String()

	stub := newPairStub()
	stubCtx, stubCancel := context.WithCancel(t.Context())
	defer stubCancel()
	go stub.Run(stubCtx, ln)

	// Provider session: handler returns an in-memory echo backend.
	provTLS := clientTLS(provCert, ca)
	prov, err := session.Dial(t.Context(), relayAddr, provTLS, provName.String(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("prov dial: %v", err)
	}
	defer prov.Close()
	if err := prov.Expose(t.Context(), "svc-echo", "in-memory", func(_ context.Context, _ *orpv1.IncomingStream) (session.Backend, error) {
		return newEchoPipe(), nil
	}); err != nil {
		t.Fatalf("prov expose: %v", err)
	}
	go func() { _ = prov.Run(t.Context()) }()

	// Consumer session.
	consTLS := clientTLS(consCert, ca)
	cons, err := session.Dial(t.Context(), relayAddr, consTLS, consName.String(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("cons dial: %v", err)
	}
	defer cons.Close()
	go func() { _ = cons.Run(t.Context()) }()

	// Wait for stub to know about both sessions and for the provider's
	// REGISTER to land.
	if !waitFor(time.Second, stub.providerReady) {
		t.Fatal("provider never registered with stub")
	}

	// Local explicit interceptor: bind one mapping and connect to it.
	probe, _ := net.Listen("tcp", "127.0.0.1:0")
	bindAddr := probe.Addr().String()
	probe.Close()
	ic, err := intercept.NewExplicit([]intercept.ExplicitMapping{
		{BindAddr: bindAddr, TargetSvc: "svc-echo"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ic.Close()

	// Glue layer: pull from interceptor, session.Dial, bridge.
	go func() {
		ctx := t.Context()
		for {
			in, err := ic.Accept(ctx)
			if err != nil {
				return
			}
			go func(in *intercept.InterceptedConn) {
				defer in.Local.Close()
				s, err := cons.Dial(ctx, in.TargetSvc, "")
				if err != nil {
					return
				}
				defer s.Close()
				done := make(chan struct{}, 2)
				go func() { _, _ = io.Copy(s, in.Local); done <- struct{}{} }()
				go func() { _, _ = io.Copy(in.Local, s); done <- struct{}{} }()
				<-done
			}(in)
		}
	}()

	// Application: dial the local bind addr and exchange bytes.
	app, err := net.Dial("tcp", bindAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	want := []byte("hello via interceptor")
	if _, err := app.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if err := readWithTimeout(app, got, 3*time.Second); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("got %q want %q", got, want)
	}
}

// pairStub is a minimal relay that:
// - accepts two agents (provider first, then consumer),
// - on REGISTER, remembers the provider's conn,
// - on consumer OPEN_STREAM, opens an INCOMING_STREAM toward provider,
// then splices the two streams.
type pairStub struct {
	provReady chan struct{}
	provConn  transport.Conn
}

func newPairStub() *pairStub { return &pairStub{provReady: make(chan struct{})} }

func (p *pairStub) providerReady() bool {
	select {
	case <-p.provReady:
		return true
	default:
		return false
	}
}

func (p *pairStub) Run(ctx context.Context, ln transport.Listener) {
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			return
		}
		go p.serve(ctx, conn)
	}
}

func (p *pairStub) serve(ctx context.Context, conn transport.Conn) {
	defer conn.Close()
	ctrl, err := conn.AcceptStream(ctx)
	if err != nil {
		return
	}
	hf, err := orp.ParseFrame(ctrl)
	if err != nil || hf.Type != orp.FrameTypeHello {
		return
	}
	if err := orp.WriteFrame(ctrl, orp.FrameTypeHelloAck, &orpv1.HelloAck{}); err != nil {
		return
	}

	go func() {
		for {
			f, err := orp.ParseFrame(ctrl)
			if err != nil {
				return
			}
			if f.Type == orp.FrameTypeRegister {
				_ = orp.WriteFrame(ctrl, orp.FrameTypeRegisterAck, &orpv1.RegisterAck{ServiceId: "svc-echo"})
				p.provConn = conn
				select {
				case <-p.provReady:
				default:
					close(p.provReady)
				}
			}
		}
	}()

	for {
		s, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go p.handleConsumerStream(ctx, s)
	}
}

func (p *pairStub) handleConsumerStream(ctx context.Context, s transport.Stream) {
	f, err := orp.ParseFrame(s)
	if err != nil || f.Type != orp.FrameTypeOpenStream {
		_ = s.Close()
		return
	}
	open := &orpv1.OpenStream{}
	_ = orp.UnmarshalProto(f, orp.FrameTypeOpenStream, open)

	<-p.provReady
	provS, err := p.provConn.OpenStream(ctx)
	if err != nil {
		_ = s.Close()
		return
	}
	defer provS.Close()
	if err := orp.WriteFrame(provS, orp.FrameTypeIncomingStream, &orpv1.IncomingStream{
		TargetService: open.TargetService,
	}); err != nil {
		return
	}
	ack, err := orp.ParseFrame(provS)
	if err != nil || ack.Type != orp.FrameTypeStreamAccept {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(provS, s); done <- struct{}{} }()
	go func() { _, _ = io.Copy(s, provS); done <- struct{}{} }()
	<-done
}

// echoPipe loops bytes written into the pipe back to readers.
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

func clientTLS(cert *tls.Certificate, ca *pki.CA) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{*cert},
		RootCAs:      ca.CertPool(),
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS13,
	}
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

func waitFor(total time.Duration, predicate func() bool) bool {
	deadline := time.Now().Add(total)
	for time.Now().Before(deadline) {
		if predicate() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}
