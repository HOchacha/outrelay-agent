// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package intercept

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
)

// ExplicitMapping binds a localhost listen address to a target service.
type ExplicitMapping struct {
	BindAddr  string // e.g. "127.0.0.1:30001"
	TargetSvc string // e.g. "svc-payments"
}

type explicitInterceptor struct {
	listeners []net.Listener
	accepts   chan *InterceptedConn
	errs      chan error
	logger    *slog.Logger

	closeOnce sync.Once
	closed    chan struct{}
}

// NewExplicit binds one listener per mapping and returns an Interceptor
// that emits InterceptedConn for each accepted local connection.
//
// On error, any listener already opened is closed before returning so
// the caller doesn't have to clean up partial state. A nil logger
// disables logging.
func NewExplicit(mappings []ExplicitMapping, logger *slog.Logger) (Interceptor, error) {
	if len(mappings) == 0 {
		return nil, errors.New("intercept: no explicit mappings")
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	ei := &explicitInterceptor{
		accepts: make(chan *InterceptedConn),
		errs:    make(chan error, 1),
		logger:  logger,
		closed:  make(chan struct{}),
	}
	for _, m := range mappings {
		ln, err := net.Listen("tcp", m.BindAddr)
		if err != nil {
			ei.closeListeners()
			logger.Warn("intercept: explicit listen failed",
				"bind", m.BindAddr, "svc", m.TargetSvc, "err", err)
			return nil, fmt.Errorf("intercept: listen %s: %w", m.BindAddr, err)
		}
		logger.Info("intercept: explicit listener bound",
			"bind", ln.Addr().String(), "svc", m.TargetSvc)
		ei.listeners = append(ei.listeners, ln)
		go ei.acceptLoop(ln, m.TargetSvc)
	}
	return ei, nil
}

func (e *explicitInterceptor) acceptLoop(ln net.Listener, svc string) {
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-e.closed:
				return
			default:
			}
			e.logger.Warn("intercept: explicit accept failed",
				"bind", ln.Addr().String(), "svc", svc, "err", err)
			// Surface the first error; subsequent errors drop on the floor.
			select {
			case e.errs <- err:
			default:
			}
			return
		}
		e.logger.Debug("intercept: explicit accepted",
			"bind", ln.Addr().String(), "svc", svc,
			"peer", c.RemoteAddr().String())
		select {
		case e.accepts <- &InterceptedConn{
			Local:     c,
			OrigDest:  ln.Addr(),
			TargetSvc: svc,
		}:
		case <-e.closed:
			_ = c.Close()
			return
		}
	}
}

func (e *explicitInterceptor) Accept(ctx context.Context) (*InterceptedConn, error) {
	select {
	case ic := <-e.accepts:
		return ic, nil
	case err := <-e.errs:
		return nil, err
	case <-e.closed:
		return nil, ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (e *explicitInterceptor) Close() error {
	e.closeOnce.Do(func() {
		close(e.closed)
		e.closeListeners()
	})
	return nil
}

func (e *explicitInterceptor) closeListeners() {
	for _, ln := range e.listeners {
		_ = ln.Close()
	}
}
