// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package forward_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	relayforward "github.com/boanlab/outrelay-relay/pkg/forward"

	agentforward "github.com/boanlab/outrelay-agent/pkg/forward"
)

// TestQUICOverForward verifies that two agents can stand up an
// end-to-end QUIC connection on top of the relay's UDP forwarding
// plane: the listener's quic.Transport sees Initial packets
// arriving on a PacketConn whose ReadFrom always reports the relay
// as the remote, and the dialer's Transport sends to that same
// relay, yet quic-go correctly routes packets via connection IDs.
//
// If quic-go ever stops tolerating "all packets share one source
// address", this test breaks and the forward-mode architecture
// needs revisiting.
func TestQUICOverForward(t *testing.T) {
	t.Parallel()

	plane, err := relayforward.NewPlane("127.0.0.1:0", slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer plane.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() { _ = plane.Run(ctx) }()

	relay := plane.Endpoint()

	// Two allocations: A (dialer), B (listener).
	allocA := plane.Allocate()
	allocB := plane.Allocate()

	// Each agent's Conn registers with the plane on Dial.
	connA, err := agentforward.Dial(relay, allocA, allocB)
	if err != nil {
		t.Fatal(err)
	}
	defer connA.Close()
	connB, err := agentforward.Dial(relay, allocB, allocA)
	if err != nil {
		t.Fatal(err)
	}
	defer connB.Close()

	// Brief wait for the plane's registration goroutine to record
	// both allocations — they were sent on Dial but the read loop
	// is async.
	dl := time.Now().Add(2 * time.Second)
	for time.Now().Before(dl) {
		_, okA := plane.Lookup(allocA)
		_, okB := plane.Lookup(allocB)
		if okA && okB {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// One self-signed cert; both ends use it (mTLS skipped — the
	// security properties are not what's under test, the
	// transport plumbing is).
	server, client := selfSignedTLS(t)

	listenerTransport := &quic.Transport{Conn: connB}
	defer listenerTransport.Close()
	dialerTransport := &quic.Transport{Conn: connA}
	defer dialerTransport.Close()

	listener, err := listenerTransport.Listen(server, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	// Listener side: accept the connection and echo one frame.
	var serverErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := listener.Accept(ctx)
		if err != nil {
			serverErr = err
			return
		}
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			serverErr = err
			return
		}
		buf := make([]byte, 5)
		if _, err := io.ReadFull(stream, buf); err != nil {
			serverErr = err
			return
		}
		if string(buf) != "hello" {
			serverErr = io.ErrUnexpectedEOF
			return
		}
		if _, err := stream.Write([]byte("world")); err != nil {
			serverErr = err
			return
		}
		_ = stream.Close()
	}()

	// Dialer side: Dial with the sentinel addr — the actual
	// destination is fixed inside Conn.WriteTo.
	dialCtx, dialCancel := context.WithTimeout(ctx, 5*time.Second)
	defer dialCancel()
	conn, err := dialerTransport.Dial(dialCtx, agentforward.PeerSentinel, client, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.CloseWithError(0, "test done")

	stream, err := conn.OpenStreamSync(dialCtx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	if _, err := stream.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 5)
	if _, err := io.ReadFull(stream, resp); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(resp) != "world" {
		t.Fatalf("got %q want %q", resp, "world")
	}

	wg.Wait()
	if serverErr != nil {
		t.Fatalf("server side: %v", serverErr)
	}
}

func selfSignedTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.0")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"mini-turn"},
			MinVersion:   tls.VersionTLS13,
		},
		&tls.Config{
			RootCAs:    pool,
			ServerName: "localhost",
			NextProtos: []string{"mini-turn"},
			MinVersion: tls.VersionTLS13,
		}
}
