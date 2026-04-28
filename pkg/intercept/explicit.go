// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package intercept

import (
	"context"
	"errors"
	"fmt"
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

	closeOnce sync.Once
	closed    chan struct{}
}

// NewExplicit binds one listener per mapping and returns an Interceptor
// that emits InterceptedConn for each accepted local connection.
//
// On error, any listener already opened is closed before returning so
// the caller doesn't have to clean up partial state.
func NewExplicit(mappings []ExplicitMapping) (Interceptor, error) {
	if len(mappings) == 0 {
		return nil, errors.New("intercept: no explicit mappings")
	}
	ei := &explicitInterceptor{
		accepts: make(chan *InterceptedConn),
		errs:    make(chan error, 1),
		closed:  make(chan struct{}),
	}
	for _, m := range mappings {
		ln, err := net.Listen("tcp", m.BindAddr)
		if err != nil {
			ei.closeListeners()
			return nil, fmt.Errorf("intercept: listen %s: %w", m.BindAddr, err)
		}
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
			// Surface the first error; subsequent errors drop on the floor.
			select {
			case e.errs <- err:
			default:
			}
			return
		}
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
