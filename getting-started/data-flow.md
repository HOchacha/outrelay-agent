# Data flow

This document follows a byte through the agent end to end. Read
[`architecture.md`](architecture.md) first for the package map.

The four flows below cover everything the agent does at runtime:

1. [Startup and connect](#1-startup-and-connect)
2. [Consumer flow](#2-consumer-flow-outbound-app-traffic) — outbound
   application traffic going out to a remote service.
3. [Provider flow](#3-provider-flow-inbound-traffic-from-the-relay)
   — inbound traffic from the relay landing on a local backend.
4. [Reconnect and stream resume](#4-reconnect-and-stream-resume)
5. [P2P promotion and demotion](#5-p2p-promotion-and-demotion)

File:line references point at the current source.

## 1. Startup and connect

```
flag parse  ->  load mTLS  ->  DialAny  ->  Expose? / startInterceptor?  ->  RunWithReconnect
```

1. **Flag parsing** (`cmd/outrelay-agent/main.go:46`). Required:
   `--cert`, `--key`, `--ca`, `--uri`. The URI is parsed via
   `identity.Parse` so a malformed value is rejected before any
   network I/O.
2. **TLS material** (`loadClientTLS`, `cmd/outrelay-agent/main.go:240`).
   Loads the X.509 keypair and CA bundle, builds a TLS 1.3 client
   config with `ServerName=--server-name`.
3. **DialAny** (`pkg/session/session.go`). Splits `--relay` on
   commas and tries each endpoint in order. The first one that
   completes HELLO wins; the rest are skipped. Failure means every
   endpoint was unreachable.
4. **Expose / interceptor wiring**. If `--expose-service` is set,
   `Session.Expose` registers the service. If `--consume` is set,
   `startInterceptor` builds the appropriate interceptor and
   `runConsumer` is launched in its own goroutine.
5. **RunWithReconnect** drives the rest of the lifetime, returning
   only on context cancellation (SIGINT / SIGTERM).

After this point the agent is ready to forward traffic.

## 2. Consumer flow (outbound app traffic)

The application talks to a remote service called `svc-payments`. The
agent intercepts the local connection and bridges it to the relay.

### Explicit dial mode

```
app -> 127.0.0.1:30001  -> explicitInterceptor.acceptLoop
                              \-> InterceptedConn{Local, TargetSvc=svc-payments}
                                  \-> runConsumer pulls it
                                      \-> Session.Dial("svc-payments")
                                          - opens QUIC stream to relay
                                          - writes OPEN_STREAM frame
                                          - returns ResumableStream
                                      \-> bridge(local, resumableStream)
```

Step by step:

1. The application opens a TCP connection to the agent's listener
   on `127.0.0.1:30001`.
   `explicitInterceptor.acceptLoop` (`pkg/intercept/explicit.go:55`)
   accepts the conn and pushes an `InterceptedConn` onto an
   internal channel.
2. `runConsumer` (`cmd/outrelay-agent/main.go:180`) calls
   `ic.Accept`, receives the `InterceptedConn`, and spawns a
   per-connection goroutine.
3. The goroutine calls `Session.Dial(ctx, "svc-payments", "")`.
   That opens a fresh QUIC stream on the existing relay connection
   and writes an `OPEN_STREAM` frame containing the target service
   name and a freshly generated `StreamID`. The returned
   `ResumableStream` wraps the QUIC stream with byte counters and
   a ring buffer.
4. `bridge(local, resumableStream)` (`cmd/outrelay-agent/main.go:209`)
   spawns two `io.Copy` goroutines and propagates a half-close on
   each direction's EOF, so the request/response round-trip
   completes cleanly even when the local side closes its writer
   first.

### tproxy mode

The first hop differs; the rest is identical to explicit mode.

```
app -> getaddrinfo("svc-payments.outrelay")
   |       (UDP query to 127.0.0.1:53 — agent's DNSServer)
   |       <- A 100.64.x.y  (VIPAllocator hands one out at startup)
   |
   v
app -> connect(100.64.x.y:<orig-port>)
   |       (iptables REDIRECT -> 127.0.0.1:15001)
   |
   v
tproxyInterceptor.acceptLoop
   - getsockopt(IP_SO_ORIGINAL_DST) -> 100.64.x.y
   - alloc.Lookup(100.64.x.y) -> "svc-payments"
   - emit InterceptedConn
```

The DNS server (`pkg/intercept/dns.go`) only answers names it knows
about — the agent calls `alloc.Allocate` for every `--consume` at
startup, and unknown names get NXDOMAIN. After that the flow
converges with explicit mode at step 2 above.

## 3. Provider flow (inbound traffic from the relay)

A consumer somewhere else has dialed `svc-orders`, the relay routes
the request to this provider's session, and the agent bridges it
into the local backend at `127.0.0.1:8080`.

```
relay -> QUIC.OpenStream toward this agent
            -> Session.Run.AcceptStream
                -> handleIncoming
                    - parse INCOMING_STREAM frame
                    - look up handler by TargetService
                    - call handler -> dial 127.0.0.1:8080
                    - reply STREAM_ACCEPT
                    - wrapStream(streamID) for resume tracking
                    - bridge(wrapped, backend)
```

Step by step:

1. `Session.Run` (`pkg/session/session.go`) is the agent's accept
   loop. Every stream the relay opens runs through `handleIncoming`.
2. `handleIncoming` reads the first frame, requires it to be
   `INCOMING_STREAM`, and looks up the registered handler for
   `in.TargetService`.
3. If no handler is registered, the agent replies `STREAM_REJECT`
   with code 404. If the handler errors, the reply is 502. Either
   way the stream is closed.
4. On success the handler returns a `Backend` (typically the
   `net.Conn` it just dialed). The agent replies `STREAM_ACCEPT`,
   wraps the relay-side stream so the §3.18 byte counters track
   matching values on both ends, and bridges the two halves.

## 4. Reconnect and stream resume

This is the agent's most subtle path and the core of §3.18.

```
RunWithReconnect loop:

  Run(ctx)                    -> returns transport error
  set reconnecting = true
  Reconnect(ctx, addrs):
     - close dead conn
     - DialQUIC + HELLO/HELLO_ACK against a healthy endpoint
     - replay REGISTER for every previously exposed service
     - for every active ResumableStream:
          Resume(ctx, rs):
             - open fresh stream on new conn
             - write STREAM_RESUME{stream_id, my_position, peer_ack}
             - read peer's echoed STREAM_RESUME
             - retransmit (peer.peer_ack, my.sent] bytes from ring
             - rs.SwapInner(new stream)
  set reconnecting = false
  Run(ctx) again
```

While the swap is in flight, every `ResumableStream.Read` /
`Write` parks on `resumeReady` instead of returning an error. The
caller's `bridge` goroutine therefore sees a brief stall and then
keeps copying bytes once the new transport is installed
(`pkg/session/session.go`).

Edge cases the code handles:

- **Endpoint failure during reconnect** — `Reconnect` iterates all
  addrs and uses the first endpoint that completes HELLO. If every
  endpoint fails, `RunWithReconnect` waits, doubles the backoff
  (cap 30 s), and tries again.
- **Stream that cannot be resumed** — `Resume` may return
  `resume.ErrBeforeRing` because the peer's ack predates the bytes
  the ring still holds. That stream is dropped with a warn log; the
  application sees a Read/Write error and reconnects at its own
  layer. Other streams keep going.
- **Asymmetric loss detection** — one side may detect the dead
  relay instantly via a QUIC `ApplicationError` while the other
  has to wait for `MaxIdleTimeout`. `ResumeRetryWindow` (30 s,
  matches `edge.ResumeWindow` on the relay) bounds how long
  Read/Write block on `SwapInner` before giving up.

`STREAM_CHECKPOINT` frames keep the ring buffer tight: the
background emitter (`pkg/session/checkpoints.go`) sends one frame
per active stream every `resume.CheckpointPeriodMs`, carrying the
sender's `MyPosition` and the bytes it has read from the peer.
The receiver applies inbound checkpoints via
`Session.applyCheckpoint`, advancing `PeerAckPos` and freeing the
prefix of the local ring buffer.

## 5. P2P promotion and demotion

When two agents can reach each other directly, the stream's data
plane can move off the relay onto a direct QUIC connection. The
control plane stays on the relay.

```
EnableP2P(ctx)        -> start controlReader goroutine

Promote(ctx, rs):
  Promoter.Run:
    1. SendOffer  -> writeCtrl(CANDIDATE_OFFER{stream_id, locals})
    2. RecvAnswer <- controlReader routes CANDIDATE_ANSWER to waiter
    3. Engine.Check(locals, peer.candidates)
       - sort by descending priority
       - for each remote candidate:
            DialQUIC with per-pair timeout (default 500 ms)
            on success: return CheckResult{Conn, Local, Remote, RTT}
       - if none works: ErrNoPair
    4. SendMigrate -> writeCtrl(MIGRATE_TO_P2P{stream_id, selected})
                        (best-effort; data path is already direct)

MigrateToDirect(ctx, rs, peerConn):
  - peerConn.OpenStream
  - write STREAM_RESUME on the direct stream
  - rs.SwapInner(direct stream)         // §3.19.5 step T5
```

`Engine.Check` reuses the same `transport.DialQUIC` the session
uses, so the direct path inherits TLS 1.3 + mTLS verification. The
remote candidates come from the peer's `CANDIDATE_ANSWER`, which
the responder builds from its own host and srflx candidates
(`pkg/candidate`).

After promotion succeeds, `Demoter.Run` watches the direct
conn for liveness via `AcceptStream`. When the peer closes or
the QUIC keepalive fires, `OnDegrade` is called once with a
`DemoteReason` and the caller drives `MIGRATE_TO_RELAY`.

The wire matcher on the relay side (the §3.19 OFFER/ANSWER
forwarder, the resume matcher, and the LRU that records
`MIGRATE_TO_P2P` selections) lives in the controller repo.

## Cross-references

The agent's source comments link into the design doc with `§<section>`:

- `§3.18` — stream resume protocol (counters, ring, STREAM_RESUME).
- `§3.18.4` — reconnect step ordering, including step T5 (SwapInner).
- `§3.18.6` — collision and edge-case handling.
- `§3.19` — P2P promotion architecture.
- `§3.19.4` — connectivity check.
- `§3.19.5` — Stream Migrator (direct STREAM_RESUME + SwapInner).
- `§3.19.6` — demotion triggers.

These all resolve to
[`OutRelay/docs/design.md`](https://github.com/boanlab/OutRelay/blob/main/docs/design.md)
in the controller repo.
