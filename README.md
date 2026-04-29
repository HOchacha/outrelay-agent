# outrelay-agent

Per-workload agent for [OutRelay](https://github.com/boanlab/OutRelay).
Runs as a Kubernetes sidecar, a Docker container on a VM, or any
other process colocated with the application.

> **Reading this in isolation?** Start at the
> [OutRelay main repo](https://github.com/boanlab/OutRelay) — it
> covers what the platform is, how the relay and controller fit
> together, how to run a relay, how to issue agent identities, and
> the wire-protocol design doc. This repo is just the agent binary.

The agent has two responsibilities:

1. Maintain a long-lived mTLS QUIC session to a relay, with
   auto-reconnect and transparent stream resume.
2. Intercept local application traffic so unmodified apps can reach
   remote services through the relay (explicit-dial or Linux tproxy).

## Layout

```
cmd/outrelay-agent/   # agent binary: flag wiring + lifecycle
pkg/
  session/            # Relay connection: HELLO, REGISTER, OPEN_STREAM,
                      # INCOMING_STREAM dispatch, DialAny failover,
                      # RunWithReconnect orchestrator, ResumableStream
                      # wrapper that parks on SwapInner during transport
                      # errors so the bridge survives a relay restart,
                      # plus Promote / MigrateToDirect for P2P
                      # promotion.
  intercept/          # Local traffic capture.
                      #   explicit.go      — one localhost listener per
                      #                      consumed service
                      #   tproxy_linux.go  — iptables REDIRECT target
                      #                      with SO_ORIGINAL_DST
                      #   dns.go           — UDP DNS server handing out
                      #                      CGNAT VIPs
                      #   vip.go           — VIP allocator over
                      #                      100.64.0.0/10
  candidate/          # P2P candidate gathering — host (local
                      # interfaces) + srflx (OBSERVED_ADDR_QUERY against
                      # the relay's built-in STUN-lite).
  p2p/                # P2P promotion engine: Engine (connectivity
                      # check), Promoter (OFFER/ANSWER →
                      # MIGRATE_TO_P2P), Demoter (path-loss / peer-close
                      # → MIGRATE_TO_RELAY).
  forward/            # Agent side of the relay's mini-TURN UDP
                      # forwarder (relay_mode=forward). A net.PacketConn
                      # that prefixes every WriteTo with the peer's
                      # 4-byte allocation id and ships to the relay's
                      # forwarding endpoint, so quic.Transport can run
                      # an end-to-end QUIC handshake on top.
deployments/          # Pod sidecar manifests, provider/consumer
                      # Deployments, plus a docker/ subdir with a
                      # `network_mode: service:outrelay-agent` compose
                      # example for VMs.
```

## Build

```bash
make build         # gofmt + golangci-lint + gosec + bin/outrelay-agent
make test          # go test -race -count=1 ./...
make build-image   # outrelay-agent:v0.1.0 + :latest
```

`go.mod` pins `github.com/boanlab/OutRelay` to a published version, so
the controller library is fetched via the Go module proxy — no sibling
checkout is required.

## Documentation

This repo's docs cover the agent's internals only. Anything cross-cutting (relay setup, dev PKI, project status, security policy) lives in the OutRelay main repo.

- [`getting-started/README.md`](getting-started/README.md) — flags,
  modes, and runnable command lines once you already have a relay
  and an agent identity.
- [`getting-started/architecture.md`](getting-started/architecture.md) —
  package map, key types, and concurrency model.
- [`getting-started/data-flow.md`](getting-started/data-flow.md) —
  request lifecycles for the consumer side, provider side,
  reconnect/resume, and P2P promotion.
- [`contribution/README.md`](contribution/README.md) — development
  workflow, style, and PR conventions for this repo.

## License

Apache 2.0 — see [`LICENSE`](LICENSE).
