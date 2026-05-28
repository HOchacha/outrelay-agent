// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

// outrelay-agent is the per-workload agent. It maintains an mTLS QUIC
// session to the relay (with auto-reconnect + transparent stream
// resume) and intercepts local application traffic in one of two
// modes — explicit dial or linux tproxy — so unmodified apps can
// reach remote services through the relay. In tproxy mode an embedded
// DNS server hands out CGNAT VIPs for the consumed services.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/boanlab/OutRelay/lib/identity"
	orpv1 "github.com/boanlab/OutRelay/lib/orp/v1"
	"github.com/boanlab/OutRelay/lib/transport"

	"github.com/boanlab/outrelay-agent/pkg/candidate"
	"github.com/boanlab/outrelay-agent/pkg/intercept"
	"github.com/boanlab/outrelay-agent/pkg/p2p"
	"github.com/boanlab/outrelay-agent/pkg/session"
)

// consumeFlag accumulates --consume entries.
//
// Format:
// --consume=<svc>@<bind-addr>          (explicit mode)
// --consume=<svc>                      (tproxy mode; VIP allocated)
type consumeFlag []string

func (c *consumeFlag) String() string     { return strings.Join(*c, ",") }
func (c *consumeFlag) Set(s string) error { *c = append(*c, s); return nil }

// Version is stamped at link time via -ldflags '-X main.Version=...'.
var Version = "dev"

func main() {
	var (
		relayAddr    = flag.String("relay", "127.0.0.1:7443", "relay address; comma-separated list for failover")
		certPath     = flag.String("cert", "", "PEM-encoded client cert")
		keyPath      = flag.String("key", "", "PEM-encoded client key")
		caPath       = flag.String("ca", "", "PEM-encoded CA bundle (relay's CA)")
		uri          = flag.String("uri", "", "agent URI (must match cert's URI SAN)")
		exposeSvc    = flag.String("expose-service", "", "service name to register (provider role)")
		exposeTo     = flag.String("expose-target", "", "local backend address (e.g. 127.0.0.1:8080)")
		mode         = flag.String("intercept", "explicit", "interception mode: explicit | tproxy")
		tproxyAddr   = flag.String("tproxy-listen", "127.0.0.1:15001", "tproxy listen address (linux REDIRECT target)")
		dnsAddr      = flag.String("dns-listen", "127.0.0.1:5353", "DNS server listen address (tproxy mode)")
		dnsSuffix    = flag.String("dns-suffix", "outrelay", "DNS suffix for service names (tproxy mode)")
		serverNm     = flag.String("server-name", "localhost", "TLS ServerName")
		p2pListen    = flag.String("p2p-listen", "", "if set (e.g. 0.0.0.0:7445), stand up a QUIC listener for inbound P2P direct dials. Empty disables the P2P-success path; the Promote code path still runs and stays on the relay.")
		p2pAdvertise = flag.String("p2p-advertise", "", "host:port to add as a high-priority candidate alongside auto-detected interface IPs. Use when the agent's external addr (e.g. an AWS EIP, GCP external IP) differs from any local interface — without this, peers see only the unroutable private IP and connectivity check fails.")
		relayTCP     = flag.String("relay-tcp", "", "comma-separated TCP+TLS+yamux relay endpoints (e.g. relay.example:443). Tried after every --relay endpoint fails. P2P promotion is disabled when the TCP fallback engages — the relay path stays available, suitable for environments that block UDP.")
		logFormat    = flag.String("log-format", "text", "log format: text or json")
		logLevel     = flag.String("log-level", "info", "log level: debug, info, warn, error")
		showVersion  = flag.Bool("version", false, "print version and exit")
	)
	var consumes consumeFlag
	flag.Var(&consumes, "consume", "consume service: <svc>@<bind-addr> (explicit) or <svc> (tproxy). Repeatable.")
	flag.Parse()
	if *showVersion {
		fmt.Println(Version)
		return
	}

	logger := newLogger(*logFormat, *logLevel)
	if *certPath == "" || *keyPath == "" || *caPath == "" || *uri == "" {
		logger.Error("missing required flags", "cert", *certPath, "key", *keyPath, "ca", *caPath, "uri", *uri)
		os.Exit(2)
	}
	if _, err := identity.Parse(*uri); err != nil {
		logger.Error("invalid agent URI", "err", err)
		os.Exit(2)
	}

	tlsConf, err := loadClientTLS(*certPath, *keyPath, *caPath, *serverNm)
	if err != nil {
		logger.Error("load tls", "err", err)
		os.Exit(1)
	}

	ctx, cancel := signalContext()
	defer cancel()

	addrs := strings.Split(*relayAddr, ",")
	for i, a := range addrs {
		addrs[i] = strings.TrimSpace(a)
	}

	// When --p2p-listen is set, the agent's outbound QUIC connection
	// to the relay AND its inbound P2P listener share a single UDP
	// socket. The relay's view of our srflx is then the same external
	// endpoint a peer would dial in to — the precondition for EIM
	// hole-punching. Without --p2p-listen, fall back to the per-Dial
	// socket model (DefaultDialer + no listener).
	var sharedTransport *transport.SharedTransport
	var sess *session.Session
	if *p2pListen != "" {
		sharedTransport, err = transport.NewSharedTransport(*p2pListen)
		if err != nil {
			logger.Error("p2p: bind shared socket", "addr", *p2pListen, "err", err)
			os.Exit(1)
		}
		// Multi-region nearest-relay routing: DialAnyHappy fires
		// concurrent dials and the fastest HELLO wins (no explicit
		// RTT probe — the dial-to-HELLO time is itself the
		// measurement). Slower attempts are cancelled.
		sess, err = session.DialAnyHappy(ctx, sharedTransport, addrs, tlsConf, *uri, logger)
		if err != nil && *relayTCP == "" {
			logger.Error("dial relay via shared transport", "err", err)
			os.Exit(1)
		}
	} else {
		sess, err = session.DialAnyHappy(ctx, transport.DefaultDialer{}, addrs, tlsConf, *uri, logger)
		if err != nil && *relayTCP == "" {
			logger.Error("dial relay", "err", err)
			os.Exit(1)
		}
	}

	// TCP+TLS fallback. Engages when QUIC dial returned no session
	// (either the QUIC path was attempted and failed, or there's
	// nothing usable). Releases the shared UDP socket since TCP
	// doesn't piggy-back on it — P2P listening is unavailable
	// while on the TCP path; the relay path stays fully functional.
	//
	// reconnectAddrs holds the endpoint list to use for Session.
	// Reconnect when the active connection drops. For QUIC mode it
	// stays as `addrs`; for TCP fallback it switches to the TCP
	// endpoint list so a relay restart doesn't redial the
	// (intentionally invalid in tests) UDP addrs.
	reconnectAddrs := addrs
	if sess == nil && *relayTCP != "" {
		if sharedTransport != nil {
			_ = sharedTransport.Close()
			sharedTransport = nil
		}
		tcpAddrs := strings.Split(*relayTCP, ",")
		for i, a := range tcpAddrs {
			tcpAddrs[i] = strings.TrimSpace(a)
		}
		sess, err = session.DialAnyHappy(ctx, transport.TCPDialer{}, tcpAddrs, tlsConf, *uri, logger)
		if err != nil {
			logger.Error("relay-tcp: all endpoints failed", "err", err)
			os.Exit(1)
		}
		reconnectAddrs = tcpAddrs
		logger.Info("agent on TCP+TLS fallback (UDP/QUIC unreachable)")
	}
	defer func() { _ = sess.Close() }()

	// Forward-mode server TLS: consumed by Session.handleIncoming
	// when an inbound stream resolves to relay_mode=FORWARD on the
	// relay (the relay sends AllocGranted instead of StreamReady).
	// Loaded unconditionally so a provider without --p2p-listen still
	// supports forward mode; the cert is the same one P2P direct
	// listening uses (single trust domain per cluster).
	if *certPath != "" && *keyPath != "" && *caPath != "" {
		fwdServerTLS, err := loadServerTLS(*certPath, *keyPath, *caPath)
		if err != nil {
			logger.Error("forward: load server tls", "err", err)
			os.Exit(1)
		}
		sess.SetForwardServerTLS(fwdServerTLS)
	}

	if *exposeSvc != "" {
		if *exposeTo == "" {
			logger.Error("--expose-service requires --expose-target")
			os.Exit(2)
		}
		err := sess.Expose(ctx, *exposeSvc, *exposeTo, func(_ context.Context, _ *orpv1.IncomingStream) (session.Backend, error) {
			c, err := net.Dial("tcp", *exposeTo)
			return c, err
		})
		if err != nil {
			logger.Error("expose", "err", err)
			os.Exit(1)
		}
		logger.Info("service registered", "name", *exposeSvc, "target", *exposeTo)
	}

	// P2P promotion wiring. EnableP2P starts the control-stream reader
	// that auto-responds to inbound CANDIDATE_OFFERs (provider side)
	// and routes CANDIDATE_ANSWERs to pending Promoter waiters
	// (consumer side). It MUST be called AFTER Expose() (or Expose's
	// REGISTER_ACK gets eaten by the reader), AFTER the listener +
	// SetLocalCandidates block (so we can run an OBSERVED_ADDR_QUERY
	// to learn our external IP without controlReader intercepting
	// the response), and BEFORE any consumer Dial / Promote call.
	p2pEngine := p2p.NewEngine(tlsConf)

	// Reuse the shared UDP socket for connectivity-check dials. Without
	// this, p2p.Engine.Check falls back to per-attempt ephemeral
	// sockets — the QUIC initial src port would no longer match the
	// agent's advertised host candidate port (= SharedTransport's
	// listener port), so the responder-side warmup punch's conntrack
	// reply tuple won't match and port-restricted NAT drops the dial.
	// With this set, the initiator's dial leaves from the same port
	// the responder pre-warmed, matching the conntrack reply tuple
	// and traversing the NAT.
	if sharedTransport != nil {
		p2pEngine.SetDialer(sharedTransport)
	}

	// Optional direct-dial listener. When --p2p-listen is set AND we
	// connected over QUIC (sharedTransport not nil), the listener
	// runs on the shared UDP socket. If we fell back to TCP,
	// sharedTransport is nil and the listener is skipped — P2P
	// promotion only makes sense over UDP.
	var p2pListener transport.Listener
	if *p2pListen != "" && sharedTransport != nil {
		serverTLS, err := loadServerTLS(*certPath, *keyPath, *caPath)
		if err != nil {
			logger.Error("p2p: load server tls", "err", err)
			os.Exit(1)
		}
		ln, err := sharedTransport.Listen(serverTLS, nil)
		if err != nil {
			logger.Error("p2p: listen on shared transport", "err", err)
			os.Exit(1)
		}
		p2pListener = ln
		defer func() { _ = ln.Close() }()

		port := uint16(ln.Addr().(*net.UDPAddr).Port) // #nosec G115 -- port is uint16 in udp
		locals := candidate.HostCandidates(port)

		// srflx auto-discovery. With a SharedTransport the agent's
		// outbound (to relay) and inbound (P2P listener) use the
		// same UDP socket; the NAT mapping for that socket —
		// whatever Cloud NAT or NAT GW assigned — is what srflx
		// returns. We advertise srflx's full ip:port verbatim
		// (NOT paired with the local listener port — under EIM the
		// NAT-assigned port can differ from the listener's, and a
		// peer must dial the NAT-assigned port for the mapping to
		// match):
		//
		//   - public-IP host: srflx == <ip>:7445, peer dials it
		//     directly (no NAT in between).
		//   - Cloud NAT EIM:  srflx == <ext_ip>:<nat_port> where
		//     nat_port != 7445; peer dials the NAT-assigned port
		//     and Cloud NAT (under EIM) routes to internal 7445.
		//   - symmetric NAT:  srflx is mapped per-destination, so
		//     the peer's dial is dropped — Engine.Check exhausts
		//     the candidate and we stay on the relay.
		srflxCtx, srflxCancel := context.WithTimeout(ctx, 5*time.Second)
		srflx, err := sess.QueryServerReflexive(srflxCtx, 3*time.Second)
		srflxCancel()
		if err != nil {
			logger.Warn("p2p: srflx query failed; continuing with host candidates only", "err", err)
		} else {
			locals = append([]candidate.Candidate{srflx}, locals...)
			logger.Info("p2p: external candidate from srflx", "addr", srflx.Addr.String(), "kind", srflx.Kind)
		}

		// Manual override (highest priority). Useful when srflx is
		// untrustworthy (e.g., dev tunnel) or the EIP is known up
		// front and we want to skip the round-trip.
		if *p2pAdvertise != "" {
			adv, err := netip.ParseAddrPort(*p2pAdvertise)
			if err != nil {
				logger.Error("p2p: invalid --p2p-advertise", "value", *p2pAdvertise, "err", err)
				os.Exit(2)
			}
			locals = append([]candidate.Candidate{{
				Kind:     "host",
				Addr:     adv,
				Priority: 100,
			}}, locals...)
		}
		sess.SetLocalCandidates(toPBCandidates(locals))
		logger.Info("p2p: listening", "addr", ln.Addr().String(), "candidates", len(locals))
	}

	// Bump per-candidate dial budget for cross-cloud RTTs and wire
	// a logger so connectivity-check failures are visible (the
	// default ErrNoPair is otherwise opaque to operators).
	p2pEngine.SetPerPairTimeout(2 * time.Second)
	p2pEngine.SetLogger(logger)

	// Now safe to start the control-stream reader.
	sess.EnableP2P(ctx)

	if p2pListener != nil {
		go func() {
			if err := sess.AcceptDirect(ctx, p2pListener); err != nil && !errors.Is(err, context.Canceled) {
				logger.Warn("p2p: accept direct stopped", "err", err)
			}
		}()
	}

	if len(consumes) > 0 {
		ic, err := startInterceptor(ctx, *mode, *tproxyAddr, *dnsAddr, *dnsSuffix, consumes, logger)
		if err != nil {
			logger.Error("start interceptor", "err", err)
			os.Exit(1)
		}
		defer func() { _ = ic.Close() }()
		go runConsumer(ctx, ic, sess, p2pEngine, tlsConf, logger)
	}

	if err := sess.RunWithReconnect(ctx, reconnectAddrs, tlsConf); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("session ended", "err", err)
		os.Exit(1)
	}
}

// startInterceptor builds the configured interceptor and (in tproxy
// mode) starts the embedded DNS server with a pre-populated VIP table.
func startInterceptor(ctx context.Context, mode, tproxyAddr, dnsAddr, dnsSuffix string, consumes consumeFlag, logger *slog.Logger) (intercept.Interceptor, error) {
	switch mode {
	case "explicit":
		var mappings []intercept.ExplicitMapping
		for _, c := range consumes {
			svc, bind, ok := strings.Cut(c, "@")
			if !ok {
				return nil, fmt.Errorf("explicit --consume must be <svc>@<bind-addr>: %q", c)
			}
			mappings = append(mappings, intercept.ExplicitMapping{
				BindAddr: bind, TargetSvc: svc,
			})
		}
		return intercept.NewExplicit(mappings, logger)

	case "tproxy":
		alloc, err := intercept.NewVIPAllocator(intercept.DefaultVIPCIDR)
		if err != nil {
			return nil, err
		}
		for _, svc := range consumes {
			vip, err := alloc.Allocate(svc)
			if err != nil {
				return nil, fmt.Errorf("allocate vip for %s: %w", svc, err)
			}
			logger.Info("vip allocated", "svc", svc, "vip", vip.String())
		}
		dns, err := intercept.NewDNSServer(dnsAddr, dnsSuffix, alloc, logger)
		if err != nil {
			return nil, err
		}
		go func() {
			if err := dns.Run(ctx); err != nil {
				logger.Error("dns server", "err", err)
			}
		}()
		return intercept.NewTProxy(tproxyAddr, alloc, logger)

	default:
		return nil, fmt.Errorf("unknown intercept mode: %s", mode)
	}
}

// runConsumer pulls each intercepted connection, dials the named
// service over the relay, and bridges the two halves. After Dial
// the relay sends one of {StreamReady, AllocGranted} on the
// agent's stream-0 ctrl: AllocGranted (relay_mode=FORWARD) means
// the data plane is the relay's UDP forwarder, with e2e QUIC built
// on top via forward.Conn — P2P promotion is skipped because the
// path is already direct between the two agents. StreamReady
// (relay_mode=SPLICE) means bytes flow over the relay-mediated
// stream, with P2P promotion attempted in the background.
func runConsumer(ctx context.Context, ic intercept.Interceptor, sess *session.Session, eng *p2p.Engine, peerClientTLS *tls.Config, logger *slog.Logger) {
	for {
		ic2, err := ic.Accept(ctx)
		if err != nil {
			if errors.Is(err, intercept.ErrClosed) || errors.Is(err, context.Canceled) {
				logger.Debug("intercept loop exiting", "err", err)
				return
			}
			logger.Error("intercept accept", "err", err)
			return
		}
		logger.Debug("intercept: new conn accepted",
			"svc", ic2.TargetSvc, "orig_dst", ic2.OrigDest.String())
		go func(in *intercept.InterceptedConn) {
			defer func() {
				logger.Debug("bridge teardown", "svc", in.TargetSvc)
				_ = in.Local.Close()
			}()
			s, err := sess.Dial(ctx, in.TargetSvc, "")
			if err != nil {
				logger.Warn("session dial", "svc", in.TargetSvc, "err", err)
				return
			}
			defer func() { _ = s.Close() }()
			logger.Debug("session: stream opened",
				"svc", in.TargetSvc, "stream_id", s.StreamID())

			// Relay always tells us the mode after policy resolves.
			// granted != nil → FORWARD; nil → SPLICE / ctx-cancelled.
			modeCtx, modeCancel := context.WithTimeout(ctx, 10*time.Second)
			granted := sess.WaitForStreamMode(modeCtx, uint64(s.StreamID()))
			modeCancel()
			if granted != nil {
				if peerClientTLS == nil {
					logger.Warn("forward: AllocGranted but no peer client TLS configured; tearing down",
						"svc", in.TargetSvc)
					return
				}
				logger.Debug("forward: dialing peer over plane",
					"svc", in.TargetSvc, "endpoint", granted.ForwardEndpoint,
					"my_alloc", granted.MyAllocation, "peer_alloc", granted.PeerAllocation)
				fs, err := session.DialForward(ctx, granted, peerClientTLS, logger)
				if err != nil {
					logger.Warn("forward: dial peer over plane failed",
						"svc", in.TargetSvc, "err", err)
					return
				}
				defer func() { _ = fs.Close() }()
				logger.Info("forward: peer connected over forwarding plane",
					"svc", in.TargetSvc, "endpoint", granted.ForwardEndpoint)
				bridge(in.Local, fs.Stream())
				return
			}

			// Splice mode: bytes flow over the relay-mediated stream.
			// tryPromote tries to upgrade to a P2P direct path in the
			// background; on failure the stream stays on the relay.
			tryPromote(ctx, sess, s, eng, in.TargetSvc, logger)
			bridge(in.Local, s)
		}(ic2)
	}
}

// tryPromote launches P2P promotion for the just-opened stream in
// the background. Failure is non-fatal — the stream stays on the
// relay path.
//
// The 1s startup delay works around a race the protocol does not
// synchronise: Session.Dial returns as soon as OPEN_STREAM is
// queued, but the relay does not record the (consumer, provider)
// pairing until *after* the provider's STREAM_ACCEPT lands. If we
// fire CANDIDATE_OFFER on the ctrl stream before that, the relay's
// peerOf lookup misses and the offer is silently dropped — the
// initiator times out waiting for ANSWER. 1s is empirically far
// past p99 OPEN_STREAM completion in the smoke topology.
func tryPromote(parent context.Context, sess *session.Session, rs *session.ResumableStream, eng *p2p.Engine, svc string, logger *slog.Logger) {
	logger.Debug("p2p: promote scheduled", "svc", svc)
	go func() {
		t0 := time.Now()
		select {
		case <-time.After(time.Second):
		case <-parent.Done():
			return
		}
		logger.Debug("p2p: promote starting",
			"svc", svc, "delay_ms", time.Since(t0).Milliseconds())
		ctx, cancel := context.WithTimeout(parent, 5*time.Second)
		defer cancel()
		res, err := sess.Promote(ctx, rs, eng, session.PromoteOptions{HostPort: 0})
		if err != nil {
			logger.Debug("p2p: stayed on relay", "svc", svc, "err", err)
			return
		}
		// Connectivity check passed — migrate the stream's inner
		// transport to the direct connection. In-flight bridge()
		// reads/writes continue without touching the relay.
		if err := sess.MigrateToDirect(ctx, rs, res.Conn); err != nil {
			logger.Warn("p2p: connectivity check passed but migrate failed; stayed on relay",
				"svc", svc, "err", err)
			_ = res.Conn.Close()
			return
		}
		logger.Info("p2p: migrated to direct",
			"svc", svc, "remote", res.Remote.String(), "rtt_ms", res.RTT.Milliseconds())
	}()
}

// bridge wires two streams in both directions and propagates a
// half-close on EOF so the round-trip can finish before either side
// is fully torn down. Without this, a one-shot client like
// `printf | nc` closes its write half right after the request, the
// bridge full-closes the local conn, and the echo reply never makes
// it back through.
func bridge(a, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(b, a)
		halfCloseWrite(b)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(a, b)
		halfCloseWrite(a)
		done <- struct{}{}
	}()
	<-done
	<-done
	_ = a.Close()
	_ = b.Close()
}

// halfCloseWrite shuts down only the write side when the underlying
// type supports it (net.TCPConn, quic.Stream via its Close). Falling
// back to full Close is correct but loses the round-trip-after-EOF
// behavior — kept as a defensive default.
func halfCloseWrite(c io.Closer) {
	type cw interface{ CloseWrite() error }
	if hc, ok := c.(cw); ok {
		_ = hc.CloseWrite()
		return
	}
	_ = c.Close()
}

// loadServerTLS builds the TLS config for the agent's inbound
// listeners (P2P direct + forward-mode peer accept). Same trust
// pool as loadClientTLS, but with ClientCAs +
// RequireAndVerifyClientCert so we authenticate the dialing peer
// (every legitimate dialer is another agent issued by the same CA).
func loadServerTLS(certPath, keyPath, caPath string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(caPath) // #nosec G304
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("tls: empty ca PEM")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// toPBCandidates copies the local Candidate list into the protobuf
// shape Session.SetLocalCandidates expects. Mirrors pkg/p2p's
// internal toPB but exists here so the agent doesn't import that
// unexported helper.
func toPBCandidates(cs []candidate.Candidate) []*orpv1.Candidate {
	out := make([]*orpv1.Candidate, 0, len(cs))
	for _, c := range cs {
		out = append(out, &orpv1.Candidate{
			Kind:     c.Kind,
			Ip:       c.Addr.Addr().String(),
			Port:     uint32(c.Addr.Port()),
			Priority: c.Priority,
		})
	}
	return out
}

func loadClientTLS(certPath, keyPath, caPath, serverName string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	// caPath comes from a flag wired by the operator, by design.
	caPEM, err := os.ReadFile(caPath) // #nosec G304
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("tls: empty ca PEM")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

func newLogger(format, level string) *slog.Logger {
	opts := &slog.HandlerOptions{Level: parseLogLevel(level)}
	var h slog.Handler
	if format == "json" {
		h = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		h = slog.NewTextHandler(os.Stderr, opts)
	}
	return slog.New(h)
}

func parseLogLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	sigC := make(chan os.Signal, 1)
	signal.Notify(sigC, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigC
		cancel()
	}()
	return ctx, cancel
}
