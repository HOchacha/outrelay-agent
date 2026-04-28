# Contributing to outrelay-agent

Thanks for your interest in contributing. This document explains the
development workflow, the quality bar enforced by CI, and the project
conventions for code, comments, and commits.

If you are unsure where to start, see
[`getting-started/`](../getting-started/) first — it walks through how
the agent fits into the OutRelay platform and how a request flows
through the code.

## Before you start

- **Open an issue first for non-trivial changes.** Bug reports,
  refactors larger than a single file, new flags, new interception
  modes, and protocol-affecting changes should all start with a GitHub
  issue so we can agree on scope. Small fixes (typos, dead code,
  internal cleanups) can go straight to a PR.
- **Stay inside the agent's responsibilities.** This repository is
  the per-workload agent: relay session management, local traffic
  interception, and §3.19 P2P promotion. The wire protocol, the relay
  itself, and the controller live in
  [`boanlab/OutRelay`](https://github.com/boanlab/OutRelay) — protocol
  changes belong there, with the agent following.
- **Security-sensitive changes need extra care.** Anything that
  touches mTLS, certificate verification, the `tproxy` socket option
  path, or VIP allocation should call that out in the PR description.

## Development environment

Required:

- **Go** — the toolchain version pinned in `go.mod` (or newer).
- **make** — wraps the build / lint / test targets used by CI.
- **Docker** — only needed for `make build-image` and the
  `deployments/docker/` example.

Optional but recommended:

- **golangci-lint** and **gosec** — `make` installs them on demand
  via `go install` if they are not already on your `PATH`. Pre-
  installing them avoids the install step on every run.
- **Linux host or VM** — `pkg/intercept/tproxy_linux.go` only builds
  on Linux. The non-Linux stub returns an error, but unit tests for
  tproxy require a real Linux kernel.

Check out the repository:

```bash
git clone https://github.com/boanlab/outrelay-agent.git
cd outrelay-agent
go mod download
```

The `go.mod` pins
[`github.com/boanlab/OutRelay`](https://github.com/boanlab/OutRelay)
to a published version, so no sibling checkout is required — the
controller library is fetched through the Go module proxy.

## Build, test, lint

Common loop:

```bash
make build           # gofmt + golangci-lint + gosec + go build -> bin/outrelay-agent
make test            # go test -race -count=1 ./...
make gofmt           # fail on gofmt drift (use `gofmt -w .` to fix)
make golangci-lint   # static analysis
make gosec           # security scan
```

CI runs all four checks plus `make build-image` on every pull request
(see [`.github/workflows/ci.yml`](../.github/workflows/ci.yml)). A PR
that fails any of them will not be merged — please run them locally
before pushing.

The race detector is mandatory for tests because the session, the
P2P promoter, and the interceptors all rely on multi-goroutine
coordination. Skipping `-race` in local runs hides real bugs.

### Container image

```bash
make build-image                       # outrelay-agent:v0.1.0 + :latest
make TAG=dev build-image               # custom tag
make TAG=v1.2.3 IMAGE=ghcr.io/me/agent build-image
```

The Dockerfile is a two-stage build that produces a distroless image
running as `nonroot`. The `VERSION` build arg is stamped into
`main.Version` at link time.

## Code style

### Formatting and linting

- All Go code must pass `gofmt`. CI fails on drift.
- All Go code must pass `golangci-lint run ./...`. The repo's
  configuration lives in [`.golangci.yml`](../.golangci.yml).
- All Go code must pass `gosec`. Where a finding is a deliberate
  false positive (for example, a syscall that needs `unsafe.Pointer`),
  add a `// #nosec G<rule>` comment with a brief reason.

### License header

Every source file starts with the SPDX header enforced by
[`.licenserc.yaml`](../.licenserc.yaml) and the `license` workflow:

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University
```

The `apache/skywalking-eyes` action runs on every PR and fails if a
new file is missing the header.

### Comments

The agent's comment policy is intentionally restrained:

- Document **why**, not **what**. Names should already explain the
  what; comments are for hidden invariants, surprising trade-offs,
  and pointers to the design-doc section that motivates the code.
- Reference the design doc with `§<section>` (for example,
  `§3.18.4 step T5`) when the code is implementing a specific
  protocol step. The full design lives in
  [`OutRelay/docs/design.md`](https://github.com/boanlab/OutRelay/blob/main/docs/design.md).
- Keep package-level docs in the file that defines the package's
  primary type. One paragraph is usually enough.
- No history, no devlog, no `// TODO(name)` ownership tags. If a
  follow-up is required, open an issue and link it from the PR.
- Do not write multi-paragraph docstrings or multi-line comment
  blocks. One short line is the default.

If you are tempted to add a comment that says "we used to do X but
now do Y", delete the old code and skip the comment — that is what
`git log` and `git blame` are for.

### No emojis

Source files, comments, commit messages, PR descriptions, and
documentation should not contain emojis. The project keeps a uniform
plain-text tone across all surfaces.

## Tests

- Tests live next to the code they cover. Files ending in `_test.go`
  use either an external `<pkg>_test` package (preferred for public
  API tests) or the internal package (for tests that need access to
  unexported helpers; suffix the file with `_internal_test.go`).
- Tests must be deterministic. If a test depends on host networking
  state (for example, `pkg/candidate.HostCandidates`), it must
  `t.Skip` gracefully when the environment is unsuitable rather than
  fail flakily — see `TestHostCandidatesNonEmpty` for the pattern.
- New behavior needs a test. Bug fixes need a regression test that
  fails before the fix and passes after.
- Integration tests that wire multiple subsystems together (relay
  stub + session + interceptor) live in `pkg/intercept/integration_test.go`.
  Real binary / container / VM tests are out of scope for this
  repository — they belong in the controller repo's e2e suite.

## Submitting a change

1. Fork the repository and create a feature branch off `main`.
   Branch names like `fix/<short>` or `feat/<short>` are fine.
2. Make your change, including tests and updated comments where
   appropriate.
3. Run `make build` and `make test` locally. Both must pass.
4. Commit with a focused message:
   - First line: imperative mood, under ~70 characters.
     (`session: drop stream when resume gap predates ring tail`)
   - Body (optional): wrap at ~72 characters; explain the *why*
     and reference the design-doc section if relevant.
   - Do not bypass commit hooks (`--no-verify`) or signing.
5. Open a pull request against `main`. Fill in the PR description
   with: what changed, why, how it was tested, and any follow-ups
   you intentionally left out.
6. Be responsive to review feedback. Squash fixups before merging
   so the history stays linear and bisectable.

Maintainers may request changes, additional tests, or a rebase. PRs
that ignore CI failures or skip the test requirement will be closed.

## Reporting bugs and security issues

- **Functional bugs that are clearly inside the agent** — file an
  issue against this repository with: the agent version
  (`outrelay-agent --version`), the relay it was talking to, the
  failing flag invocation, a minimal reproduction, and observed vs.
  expected behavior.
- **Anything else** — wire-protocol questions, relay/controller
  issues, security vulnerabilities, and the project security policy
  are all handled in the OutRelay main repo:
  [boanlab/OutRelay](https://github.com/boanlab/OutRelay). When in
  doubt, file there; it can be moved if it turns out to be agent-only.

## License

By contributing, you agree that your contributions will be licensed
under the [Apache License 2.0](../LICENSE) — the same license the
rest of the project uses. The SPDX header on each file makes the
licensing explicit; do not add files without one.
