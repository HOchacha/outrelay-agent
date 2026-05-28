// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

//go:build !linux

package intercept

import (
	"errors"
	"log/slog"
)

// NewTProxy is a stub on non-linux: SO_ORIGINAL_DST is a linux-specific
// netfilter feature. On macOS / Windows the agent must use explicit
// dial mode.
func NewTProxy(listenAddr string, alloc *VIPAllocator, logger *slog.Logger) (Interceptor, error) {
	return nil, errors.New("intercept: tproxy mode requires linux")
}
