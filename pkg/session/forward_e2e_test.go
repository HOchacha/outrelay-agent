// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package session_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/boanlab/OutRelay/lib/control/v1"
	"github.com/boanlab/OutRelay/lib/identity"
	orpv1 "github.com/boanlab/OutRelay/lib/orp/v1"
	"github.com/boanlab/OutRelay/lib/transport"
	"github.com/boanlab/OutRelay/pkg/pki"
	ctrlreg "github.com/boanlab/OutRelay/pkg/registry"
	"github.com/boanlab/OutRelay/pkg/registry/store"

	"github.com/boanlab/outrelay-relay/pkg/edge"
	"github.com/boanlab/outrelay-relay/pkg/forward"
	"github.com/boanlab/outrelay-relay/pkg/policy"
	relayreg "github.com/boanlab/outrelay-relay/pkg/registry"

	"github.com/boanlab/outrelay-agent/pkg/session"
)

// TestE2EForwardModeRoundTrip is the agent-integration counterpart
// to outrelay-relay's TestE2EConsumerProviderSplice but for
// relay_mode=FORWARD. It stands up:
//
//   - a real edge.Server with a forward.Plane on UDP/127.0.0.1:0
//   - a policy whose only rule says svc-fwd uses relay_mode=FORWARD
//   - a TCP echo backend
//   - two real *session.Session, one provider one consumer
//
// and verifies that:
//
//  1. The relay sends AllocGranted (not StreamReady) on the
//     consumer's and provider's stream-0 ctrl.
//  2. session.DialForward / session.AcceptForward open a forward.Conn
//     per side, run quic.Transport over it, and complete an e2e QUIC
//     handshake whose every datagram traverses the relay's UDP
//     forwarding plane.
//  3. Bytes written by the consumer arrive at the provider's TCP
//     echo backend and the response makes the round trip.
func TestE2EForwardModeRoundTrip(t *testing.T) {
	t.Parallel()

	ca, err := pki.NewCA()
	if err != nil {
		t.Fatal(err)
	}
	relayName, _ := identity.NewAgent("acme")
	provName, _ := identity.NewAgent("acme")
	consName, _ := identity.NewAgent("acme")

	relayCert := issueLeaf(t, ca, relayName)
	provCert := issueLeaf(t, ca, provName)
	consCert := issueLeaf(t, ca, consName)

	// Local TCP echo backend.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()

	// Forward plane bound to an ephemeral UDP port.
	plane, err := forward.NewPlane("127.0.0.1:0", slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer plane.Close()
	planeCtx, planeCancel := context.WithCancel(t.Context())
	defer planeCancel()
	go func() { _ = plane.Run(planeCtx) }()

	// Policy: a target-exact rule forces relay_mode=FORWARD on
	// svc-fwd; a wildcard catch-all keeps the callee-side check
	// (caller=provider, target=consumer URI) from defaulting to
	// closed-world deny.
	eng := policy.NewEngine()
	eng.Set([]*policy.Rule{
		{
			ID:            "fwd",
			CallerPattern: "*",
			TargetPattern: "svc-fwd",
			Decision:      policy.DecisionAllow,
			RelayMode:     policy.RelayModeForward,
		},
		{
			ID:            "allow-all",
			CallerPattern: "*",
			TargetPattern: "*",
			Decision:      policy.DecisionAllow,
		},
	})

	// Relay listener on an ephemeral QUIC port + in-process controller.
	srvTLS := &tls.Config{
		Certificates: []tls.Certificate{*relayCert},
		ClientCAs:    ca.CertPool(),
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
	ln, err := transport.ListenQUIC("127.0.0.1:0", srvTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctrlClient := startInProcessControllerForFwd(t)
	reg := relayreg.New(ctrlClient, "relay-fwd", "")

	srv := edge.New(ln.Addr().String(), nil, reg, eng, policy.NewCache(), nil, nil, plane, nil, slog.New(slog.DiscardHandler))
	relayCtx, relayCancel := context.WithCancel(t.Context())
	defer relayCancel()
	go func() { _ = srv.RunListener(relayCtx, ln) }()

	relayAddr := ln.Addr().String()

	// Provider session: connect with mTLS, register svc-fwd, set
	// forward server TLS, EnableP2P (controlReader needed for
	// AllocGranted dispatch), Run.
	provTLS := agentClientTLS(provCert, ca)
	provSess, err := session.Dial(t.Context(), relayAddr, provTLS, provName.String(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("provider session.Dial: %v", err)
	}
	defer provSess.Close()

	provServerTLS := agentServerTLS(provCert, ca)
	provSess.SetForwardServerTLS(provServerTLS)

	// Provider's IncomingHandler dials the local echo TCP backend on
	// each accepted stream. When AcceptForward sets up the e2e QUIC
	// connection over forward.Conn, handleIncoming bridges the
	// accepted QUIC stream to this backend.
	if err := provSess.Expose(t.Context(), "svc-fwd", echoLn.Addr().String(), func(_ context.Context, _ *orpv1.IncomingStream) (session.Backend, error) {
		return net.Dial("tcp", echoLn.Addr().String())
	}); err != nil {
		t.Fatalf("provider Expose: %v", err)
	}

	provSess.EnableP2P(t.Context())

	provRunCtx, provRunCancel := context.WithCancel(t.Context())
	defer provRunCancel()
	go func() { _ = provSess.Run(provRunCtx) }()

	// Wait for controller to learn the registration so the consumer's
	// OPEN_STREAM resolves.
	if !waitForFwd(2*time.Second, func() bool {
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		resp, err := ctrlClient.Resolve(ctx, &pb.ResolveRequest{Tenant: "acme", ServiceName: "svc-fwd"})
		return err == nil && len(resp.Providers) > 0
	}) {
		t.Fatal("svc-fwd never registered")
	}

	// Consumer session.
	consTLS := agentClientTLS(consCert, ca)
	consSess, err := session.Dial(t.Context(), relayAddr, consTLS, consName.String(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("consumer session.Dial: %v", err)
	}
	defer consSess.Close()

	consSess.EnableP2P(t.Context())

	// Consumer Run isn't strictly needed (no inbound streams to dispatch),
	// but EnableP2P alone gives us controlReader for AllocGranted.

	// Open the stream. The relay will see the policy says FORWARD,
	// allocate ids, and send AllocGranted to both ctrl streams.
	rs, err := consSess.Dial(t.Context(), "svc-fwd", "")
	if err != nil {
		t.Fatalf("consumer Dial svc-fwd: %v", err)
	}
	defer rs.Close()

	modeCtx, modeCancel := context.WithTimeout(t.Context(), 30*time.Second)
	granted := consSess.WaitForStreamMode(modeCtx, uint64(rs.StreamID()))
	modeCancel()
	if granted == nil {
		t.Fatal("consumer never received AllocGranted (got StreamReady or timeout)")
	}
	if granted.MyAllocation == 0 || granted.PeerAllocation == 0 || granted.ForwardEndpoint == "" {
		t.Fatalf("AllocGranted incomplete: %+v", granted)
	}

	// Bring up the consumer's e2e QUIC dial over the forward plane.
	// Use InsecureSkipVerify here because the peer cert's URI SAN is
	// from the agent CA but the ServerName the dialer would set is
	// arbitrary in forward mode — production hardening is to plumb
	// the peer's URI through AllocGranted and verify against it.
	dialPeerTLS := &tls.Config{
		Certificates:       []tls.Certificate{*consCert},
		RootCAs:            ca.CertPool(),
		InsecureSkipVerify: true, //nolint:gosec // peer URI verification is follow-up
		ServerName:         "peer",
		MinVersion:         tls.VersionTLS13,
	}
	// 30s ceiling: in-process round trip is ~ms locally, but CI
	// runners with constrained UDP buffers and contention sometimes
	// take seconds to complete the e2e QUIC handshake.
	dialCtx, dialCancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer dialCancel()
	fs, err := session.DialForward(dialCtx, granted, dialPeerTLS)
	if err != nil {
		t.Fatalf("DialForward: %v", err)
	}
	defer fs.Close()

	// Round-trip a payload through:
	//   consumer → forward.Conn → relay UDP plane → forward.Conn → provider
	//   provider's AcceptForward stream → bridge → TCP echo
	want := []byte("hello-via-forward-plane")
	if _, err := fs.Stream().Write(want); err != nil {
		t.Fatalf("write: %v", err)
	}

	got := make([]byte, len(want))
	readDone := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(fs.Stream(), got)
		readDone <- err
	}()
	select {
	case err := <-readDone:
		if err != nil {
			t.Fatalf("read: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("timed out waiting for echo through forward plane")
	}
	if string(got) != string(want) {
		t.Fatalf("echo mismatch: got %q want %q", got, want)
	}

	// Verify the relay's plane recorded both allocations (i.e. both
	// agents successfully registered via their forward.Dial calls).
	if _, ok := plane.Lookup(granted.MyAllocation); !ok {
		t.Errorf("plane has no record of consumer allocation %d", granted.MyAllocation)
	}
	if _, ok := plane.Lookup(granted.PeerAllocation); !ok {
		t.Errorf("plane has no record of provider allocation %d", granted.PeerAllocation)
	}

	// Best-effort drain: close consumer rs explicitly so the relay
	// exits its FORWARD park loop and frees allocations.
	_ = rs.Close()

	// Tiny grace period for the relay to free state.
	time.Sleep(100 * time.Millisecond)
}

// agentClientTLS builds the same client-side mTLS config the real
// outrelay-agent main.go does (cert + CA + server name).
func agentClientTLS(cert *tls.Certificate, ca *pki.CA) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{*cert},
		RootCAs:      ca.CertPool(),
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS13,
	}
}

// agentServerTLS mirrors loadServerTLS in agent main.go: same trust
// pool, RequireAndVerifyClientCert. SetForwardServerTLS uses this for
// the e2e QUIC listener side.
func agentServerTLS(cert *tls.Certificate, ca *pki.CA) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{*cert},
		ClientCAs:    ca.CertPool(),
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
}

func issueLeaf(t *testing.T, ca *pki.CA, name identity.Name) *tls.Certificate {
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

func waitForFwd(total time.Duration, predicate func() bool) bool {
	deadline := time.Now().Add(total)
	for time.Now().Before(deadline) {
		if predicate() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// startInProcessControllerForFwd is the same in-process controller
// shim outrelay-relay/pkg/edge's e2e tests use, copied here to keep
// the agent module test self-contained.
func startInProcessControllerForFwd(t *testing.T) pb.RegistryClient {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	st, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	pb.RegisterRegistryServer(gs, ctrlreg.New(st))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = gs.Serve(ln) }()
	t.Cleanup(func() { gs.GracefulStop(); _ = st.Close() })

	cc, err := grpc.NewClient(ln.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	return pb.NewRegistryClient(cc)
}
