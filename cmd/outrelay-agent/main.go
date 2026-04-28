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
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/boanlab/OutRelay/lib/identity"
	orpv1 "github.com/boanlab/OutRelay/lib/orp/v1"

	"github.com/boanlab/outrelay-agent/pkg/intercept"
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
		relayAddr   = flag.String("relay", "127.0.0.1:7443", "relay address; comma-separated list for failover")
		certPath    = flag.String("cert", "", "PEM-encoded client cert")
		keyPath     = flag.String("key", "", "PEM-encoded client key")
		caPath      = flag.String("ca", "", "PEM-encoded CA bundle (relay's CA)")
		uri         = flag.String("uri", "", "agent URI (must match cert's URI SAN)")
		exposeSvc   = flag.String("expose-service", "", "service name to register (provider role)")
		exposeTo    = flag.String("expose-target", "", "local backend address (e.g. 127.0.0.1:8080)")
		mode        = flag.String("intercept", "explicit", "interception mode: explicit | tproxy")
		tproxyAddr  = flag.String("tproxy-listen", "127.0.0.1:15001", "tproxy listen address (linux REDIRECT target)")
		dnsAddr     = flag.String("dns-listen", "127.0.0.1:5353", "DNS server listen address (tproxy mode)")
		dnsSuffix   = flag.String("dns-suffix", "outrelay", "DNS suffix for service names (tproxy mode)")
		serverNm    = flag.String("server-name", "localhost", "TLS ServerName")
		logFormat   = flag.String("log-format", "text", "log format: text or json")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	var consumes consumeFlag
	flag.Var(&consumes, "consume", "consume service: <svc>@<bind-addr> (explicit) or <svc> (tproxy). Repeatable.")
	flag.Parse()
	if *showVersion {
		fmt.Println(Version)
		return
	}

	logger := newLogger(*logFormat)
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
	sess, err := session.DialAny(ctx, addrs, tlsConf, *uri, logger)
	if err != nil {
		logger.Error("dial relay", "err", err)
		os.Exit(1)
	}
	defer func() { _ = sess.Close() }()

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

	if len(consumes) > 0 {
		ic, err := startInterceptor(ctx, *mode, *tproxyAddr, *dnsAddr, *dnsSuffix, consumes, logger)
		if err != nil {
			logger.Error("start interceptor", "err", err)
			os.Exit(1)
		}
		defer func() { _ = ic.Close() }()
		go runConsumer(ctx, ic, sess, logger)
	}

	if err := sess.RunWithReconnect(ctx, addrs, tlsConf); err != nil && !errors.Is(err, context.Canceled) {
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
		return intercept.NewExplicit(mappings)

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
		dns, err := intercept.NewDNSServer(dnsAddr, dnsSuffix, alloc)
		if err != nil {
			return nil, err
		}
		go func() {
			if err := dns.Run(ctx); err != nil {
				logger.Error("dns server", "err", err)
			}
		}()
		return intercept.NewTProxy(tproxyAddr, alloc)

	default:
		return nil, fmt.Errorf("unknown intercept mode: %s", mode)
	}
}

// runConsumer pulls each intercepted connection, dials the named
// service over the relay, and bridges the two halves.
func runConsumer(ctx context.Context, ic intercept.Interceptor, sess *session.Session, logger *slog.Logger) {
	for {
		ic2, err := ic.Accept(ctx)
		if err != nil {
			if errors.Is(err, intercept.ErrClosed) || errors.Is(err, context.Canceled) {
				return
			}
			logger.Error("intercept accept", "err", err)
			return
		}
		go func(in *intercept.InterceptedConn) {
			defer in.Local.Close()
			s, err := sess.Dial(ctx, in.TargetSvc, "")
			if err != nil {
				logger.Warn("session dial", "svc", in.TargetSvc, "err", err)
				return
			}
			defer func() { _ = s.Close() }()
			bridge(in.Local, s)
		}(ic2)
	}
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

func newLogger(format string) *slog.Logger {
	var h slog.Handler
	if format == "json" {
		h = slog.NewJSONHandler(os.Stderr, nil)
	} else {
		h = slog.NewTextHandler(os.Stderr, nil)
	}
	return slog.New(h)
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
