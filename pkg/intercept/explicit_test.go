// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package intercept_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/boanlab/outrelay-agent/pkg/intercept"
)

func TestExplicitInterceptor(t *testing.T) {
	t.Parallel()

	// The interceptor doesn't expose its bound listener addresses, so
	// the test pre-allocates two ephemeral ports by opening probe
	// listeners and closing them before NewExplicit binds. There is a
	// small race window if the OS reuses the port, but it is
	// acceptable for a unit test.
	probe1, _ := net.Listen("tcp", "127.0.0.1:0")
	probe2, _ := net.Listen("tcp", "127.0.0.1:0")
	addr1 := probe1.Addr().String()
	addr2 := probe2.Addr().String()
	probe1.Close()
	probe2.Close()

	ic2, err := intercept.NewExplicit([]intercept.ExplicitMapping{
		{BindAddr: addr1, TargetSvc: "svc-payments"},
		{BindAddr: addr2, TargetSvc: "svc-orders"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ic2.Close()

	// Connect to mapping #1
	c, err := net.Dial("tcp", addr1)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	got, err := ic2.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.TargetSvc != "svc-payments" {
		t.Fatalf("svc=%s want svc-payments", got.TargetSvc)
	}
	got.Local.Close()

	// Connect to mapping #2
	c2, err := net.Dial("tcp", addr2)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()

	got2, err := ic2.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got2.TargetSvc != "svc-orders" {
		t.Fatalf("svc=%s want svc-orders", got2.TargetSvc)
	}
	got2.Local.Close()
}

func TestExplicitInterceptorCloseUnblocksAccept(t *testing.T) {
	t.Parallel()
	ic, err := intercept.NewExplicit([]intercept.ExplicitMapping{
		{BindAddr: "127.0.0.1:0", TargetSvc: "svc-x"},
	})
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := ic.Accept(t.Context())
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	_ = ic.Close()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error after Close")
		}
	case <-time.After(time.Second):
		t.Fatal("Accept did not return after Close")
	}
}
