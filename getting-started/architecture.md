# Architecture

This document maps the source layout to the responsibilities each
package owns. Read [`README.md`](README.md) first for the runtime
view; read this when you need to know which file to open.

## Repository layout

```
cmd/outrelay-agent/   # main binary: flag parsing, wiring, lifecycle
pkg/
  session/            # mTLS QUIC session to the relay + stream resume
  intercept/          # local traffic capture (explicit + tproxy + DNS + VIP)
  candidate/          # P2P candidate gathering (host + server-reflexive)
  p2p/                # P2P promotion engine + demoter
deployments/          # k8s manifests, sidecar example, docker compose
.github/workflows/    # CI: gofmt, golangci-lint, gosec, test, build-image
```

The agent depends on `github.com/boanlab/OutRelay` for the wire
protocol library (`lib/orp`, `lib/orp/v1` proto types,
`lib/transport` QUIC abstraction, `lib/resume` byte-counter / ring
state, `lib/identity` URI parsing, `pkg/pki` for tests). All
protocol changes happen there first; this repo follows.

## Components

### `cmd/outrelay-agent`

The binary entry point. Parses flags, loads the mTLS material,
constructs the session, optionally registers a service, optionally
starts an interceptor, and finally runs `Session.RunWithReconnect`
until SIGINT/SIGTERM.

Key functions:

- `main` (`cmd/outrelay-agent/main.go`) — flag wiring + lifecycle.
- `startInterceptor` — picks `intercept.NewExplicit` or
  `intercept.NewTProxy` based on `--intercept`; in tproxy mode also
  pre-allocates VIPs and boots the embedded DNS server.
- `runConsumer` — pulls intercepted connections, calls
  `Session.Dial`, and bridges the two halves.
- `bridge` / `halfCloseWrite` — copy bytes in both directions and
  propagate a half-close on EOF so one-shot request/response
  exchanges (e.g. `printf | nc`) survive the local writer closing.

### `pkg/session`

Owns the QUIC connection to the relay and the protocol state on top
of it.

| Type / function | Responsibility |
|---|---|
| `Session` | The agent's relay connection. Holds the QUIC `Conn`, the control `Stream`, the registered handler map, and the active stream wrappers. |
| `Dial` / `DialAny` | HELLO handshake against one or many relay endpoints. `DialAny` returns the first endpoint that completes HELLO. |
| `Expose` | Sends `REGISTER` and binds an `IncomingHandler` for the named service. |
| `Dial` (method) | Opens a stream toward a remote service via `OPEN_STREAM`. Returns a `ResumableStream`. |
| `ResumableStream` | Wraps a `transport.Stream` with the §3.18 byte counters and ring buffer. `Read` / `Write` park on `SwapInner` while a reconnect is in flight, so applications see a brief stall instead of a stream error. |
| `Run` | Blocks accepting incoming streams and dispatching `INCOMING_STREAM` frames to the registered handler. |
| `RunWithReconnect` | Wraps `Run` in a loop that re-dials and replays `REGISTER` + `STREAM_RESUME` after every conn loss, with exponential backoff capped at 30 s. |
| `StartResume` (`checkpoints.go`) | Background goroutines that emit periodic `STREAM_CHECKPOINT` frames and apply inbound ones to the per-stream resume state. |
| `EnableP2P` / `Promote` / `MigrateToDirect` (`promote.go`) | §3.19 promotion: gather candidates, exchange OFFER/ANSWER, run connectivity check, swap the stream's inner transport over to the direct conn. |

The control-stream reader (`controlReader` in `promote.go`) is the
single dispatcher for inbound control frames: it routes
`CANDIDATE_ANSWER` to a per-stream-id waiter, auto-replies to
`CANDIDATE_OFFER`, and feeds `STREAM_CHECKPOINT` into the resume
state. It is started exactly once via `ctrlReaderOnce`.

### `pkg/intercept`

Turns local application traffic into target service names.

| Type | Mode | Notes |
|---|---|---|
| `Interceptor` | both | Common interface: `Accept` returns the next `InterceptedConn`; `Close` stops accepting. |
| `InterceptedConn` | both | A hijacked local connection plus the resolved `TargetSvc`. |
| `NewExplicit` (`explicit.go`) | explicit | One `net.Listener` per `ExplicitMapping`. The application dials a known localhost address. |
| `NewTProxy` (`tproxy_linux.go`) | tproxy | One TCP listener bound to `--tproxy-listen`. After accepting, calls `getsockopt(IP_SO_ORIGINAL_DST)` to recover the destination, then reverse-looks-up the VIP via the allocator. |
| `NewTProxy` (`tproxy_other.go`) | tproxy | Stub on non-Linux — returns an error. |
| `VIPAllocator` (`vip.go`) | tproxy | Hands out unique IPs from `100.64.0.0/10` (CGNAT) for service names; supports forward and reverse lookup. |
| `DNSServer` (`dns.go`) | tproxy | UDP DNS server that answers A queries for the configured suffix (default `outrelay`) by mapping `<svc>.<suffix>` to the allocated VIP. AAAA returns NXDOMAIN. |

### `pkg/candidate`

Builds the agent's reachable-address list for §3.19 P2P promotion.

- `HostCandidates(port)` — every non-loopback / non-link-local IP on
  a local interface, paired with the agent's negotiated session
  port. Priorities follow a simplified RFC 8445 ordering (global >
  private; v6 preferred over v4 within each class).
- `QueryServerReflexive` — sends `OBSERVED_ADDR_QUERY` on the
  control stream and waits for the matching `OBSERVED_ADDR_RESP`,
  yielding an `srflx` candidate (the relay's view of this agent's
  source ip:port).
- `Sort` — descending priority, stable for ties.

### `pkg/p2p`

Drives §3.19 promotion and demotion against a candidate-pair matrix.

- `Engine.Check` — iterates remote candidates in priority order and
  attempts a direct QUIC dial against each, capped by a per-pair
  timeout (default 500 ms). Returns the first pair whose handshake
  completes.
- `Promoter.Run` — the four-step orchestration: send OFFER, wait
  for ANSWER, run `Engine.Check`, signal `MIGRATE_TO_P2P`. The
  transport hooks (`SendOffer`, `RecvAnswer`, `SendMigrate`) are
  function fields so the promoter can be unit-tested without a real
  control stream.
- `Demoter.Run` — watches the direct conn for liveness failure via
  `AcceptStream`. When the peer's QUIC layer signals an error (peer
  close, idle timeout), `OnDegrade` is called once with a
  `DemoteReason` and the caller drives `MIGRATE_TO_RELAY`.

## Roles: provider, consumer, both

A running agent is described by which combinations of flags are set:

- **Provider only** — `--expose-service` + `--expose-target`. Calls
  `Session.Expose`. The session's `Run` dispatches inbound
  `INCOMING_STREAM` frames to the handler, which dials the target.
- **Consumer only** — `--consume` (one or more). Boots an
  interceptor; `runConsumer` pulls from it and calls `Session.Dial`
  per intercepted connection.
- **Both** — combine the above. Nothing in the session prevents one
  agent from doing both at once.

## Concurrency model

- The session has one foreground goroutine per active call into
  `Session.Run` and one per `runConsumer` accept loop. Each accepted
  stream spawns a short-lived goroutine that runs `bridge`.
- `Session.ctrlWriteMu` serializes writes onto the control stream
  so the foreground (`Expose` / `Resume` / `Promote` / `Migrate`)
  and the background `controlReader` cannot interleave frames.
- `Session.mu` (RWMutex) protects the handler and stream maps.
- `ResumableStream.mu` (RWMutex) protects `inner` + `resumeReady`
  during a `SwapInner`.
- `Session.reconnecting` (atomic bool) is the signal that
  `RunWithReconnect` is between detecting conn loss and finishing
  `Reconnect`. Read/Write on resumable streams checks it to decide
  whether to park on `SwapInner` or fail through.

## Resilience features

| Feature | Where | Why |
|---|---|---|
| Endpoint failover | `DialAny` (`session.go`) | Try every relay LB endpoint until one completes HELLO. |
| Auto reconnect | `RunWithReconnect` (`session.go`) | Re-dial on conn loss, exponential backoff (cap 30 s), replay REGISTER for every exposed service, replay STREAM_RESUME for every active stream. |
| Stream resume | `ResumableStream` + `Reconnect` | Byte counters + ring buffer let the relay's matcher pair the halves on the new transport and retransmit only the bytes the peer hasn't acked. Bridge sees a brief stall, not a tear-down. |
| P2P promotion | `Promote` / `MigrateToDirect` | Move a stream off the relay onto a direct QUIC connection between the two agents when reachability allows it. |
| P2P demotion | `Demoter` | Detect a dead direct conn and trigger fall-back to relay. |
| TLS 1.3 + mTLS | `loadClientTLS` (`main.go`) | Both sides authenticated by their leaf certs; URI SAN identifies the agent. |

## What this repo does *not* do

- It does not implement the relay. The relay terminates QUIC from
  agents, runs the splice, and operates the §3.19 OFFER/ANSWER
  matcher. See [`boanlab/OutRelay`](https://github.com/boanlab/OutRelay).
- It does not implement the controller (CRDs, service catalog,
  identity issuance). The controller and dev PKI also live in the
  controller repo.
- It does not parse application-layer protocols. The agent splices
  raw bytes between the local conn and the relay-side stream; HTTP,
  gRPC, etc. ride on top transparently.
