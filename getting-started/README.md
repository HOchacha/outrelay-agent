# Getting started

This guide covers the agent binary in isolation: its flags, the two
interception modes, and the runnable command lines for each role.

> **You should arrive here from the
> [OutRelay main repo](https://github.com/boanlab/OutRelay).** The
> main repo is responsible for everything that lives outside the
> agent process — what OutRelay is, how to run a relay, how to issue
> agent identities (cert + key + CA + URI), and the wire-protocol
> design doc. This page assumes those are already in place.

Read next:

- [`architecture.md`](architecture.md) — components, packages, and
  how they fit together.
- [`data-flow.md`](data-flow.md) — what happens when a byte enters
  the agent, end to end.

## What the agent does

1. **Maintains a long-lived mTLS QUIC session to a relay.** Carries a
   control stream (HELLO / REGISTER / OFFER / ANSWER / MIGRATE /
   CHECKPOINT frames) plus on-demand application streams. If the
   relay restarts or fails over, the session reconnects automatically
   and resumes every active application stream from the last byte
   the peer acknowledged — applications see a brief stall instead of
   a broken connection.

2. **Intercepts local application traffic** so unmodified apps can
   reach remote services through the relay:
   - **explicit dial** — the agent listens on `127.0.0.1:<port>` for
     each consumed service; the application dials that port directly.
     No special privileges, works on every platform.
   - **tproxy** — Linux iptables `REDIRECT` sends outgoing TCP to
     the agent's proxy port; the agent recovers the original
     destination via `SO_ORIGINAL_DST` and looks the IP up in a
     CGNAT VIP table. An embedded UDP DNS server hands out the VIPs
     in the first place. Requires `CAP_NET_ADMIN`.

A single agent instance can simultaneously **provide** services
(register a local backend with the relay) and **consume** services
(intercept outbound traffic and bridge it to remote backends).

## Flags

| Flag | Default | Purpose |
|---|---|---|
| `--relay` | `127.0.0.1:7443` | Comma-separated relay endpoints. The agent dials the first healthy one and re-dials on conn loss. |
| `--uri` | (required) | Agent URI; must match the cert's URI SAN. |
| `--cert` / `--key` / `--ca` | (required) | mTLS material. |
| `--server-name` | `localhost` | TLS `ServerName`. Production should set this to the relay cert's name. |
| `--intercept` | `explicit` | `explicit` or `tproxy`. |
| `--consume` | (repeatable) | `<svc>@<bind-addr>` in explicit mode, `<svc>` in tproxy mode. |
| `--expose-service` / `--expose-target` | — | Register a local backend with the relay. |
| `--tproxy-listen` | `127.0.0.1:15001` | tproxy proxy port. |
| `--dns-listen` | `127.0.0.1:5353` | Embedded DNS server bind address (tproxy mode). |
| `--dns-suffix` | `outrelay` | DNS suffix for service names (tproxy mode). |
| `--log-format` | `text` | `text` or `json`. |
| `--version` | — | Print the build version stamped at link time and exit. |

## Run

### Consumer — explicit mode

The simplest path; works on every OS:

```bash
outrelay-agent \
  --relay relay-a:7443,relay-b:7443,relay-c:7443 \
  --uri  outrelay://acme/agent/<uuid> \
  --cert /etc/outrelay/tls.crt --key /etc/outrelay/tls.key \
  --ca   /etc/outrelay/ca.crt \
  --intercept explicit \
  --consume svc-payments@127.0.0.1:30001
```

The application then dials `127.0.0.1:30001` and the agent bridges
each connection to `svc-payments` over the relay.

### Consumer — tproxy mode

Transparent capture on Linux:

```bash
outrelay-agent \
  --relay relay-a:7443 \
  --uri  outrelay://acme/agent/<uuid> \
  --cert /etc/outrelay/tls.crt --key /etc/outrelay/tls.key \
  --ca   /etc/outrelay/ca.crt \
  --intercept tproxy \
  --tproxy-listen 127.0.0.1:15001 \
  --dns-listen    127.0.0.1:53 \
  --dns-suffix    outrelay \
  --consume svc-payments
```

The Pod / VM also needs an iptables rule that REDIRECTs CGNAT
destinations to the proxy port, and `/etc/resolv.conf` must point at
the agent's DNS:

```bash
iptables -t nat -A OUTPUT \
  -p tcp -d 100.64.0.0/10 \
  -j REDIRECT --to-port 15001
```

The application then dials `svc-payments.outrelay`, the agent's DNS
returns a CGNAT VIP, the iptables rule REDIRECTs the connection to
the proxy port, and the agent reverse-looks-up the VIP to recover
the service name.

### Provider

```bash
outrelay-agent \
  --relay relay-a:7443 \
  --uri  outrelay://acme/agent/<uuid> \
  --cert /etc/outrelay/tls.crt --key /etc/outrelay/tls.key \
  --ca   /etc/outrelay/ca.crt \
  --expose-service svc-orders \
  --expose-target  127.0.0.1:8080
```

When the relay forwards an `INCOMING_STREAM` for `svc-orders`, the
agent dials `127.0.0.1:8080` and bridges the relay-side stream with
the local backend.

### Both at once

Repeat `--consume` and add `--expose-*` to make a single agent both
consume and provide services.

## Deployment manifests

Working examples live under [`../deployments/`](../deployments/):

- `30-outrelay-provider.yaml` — Kubernetes Deployment that exposes
  `svc-echo` backed by a `socat` cat-loop.
- `40-outrelay-consumer.yaml` — Kubernetes Deployment that holds a
  long-lived `nc` connection through the agent. Useful for
  exercising stream resume by deleting and recreating relay Pods.
- `sidecar-example.yaml` — annotated reference manifest for app
  authors writing their own sidecar.
- `docker/docker-compose.yaml` — VM deployment using
  `network_mode: service:outrelay-agent`.

The TLS Secrets these manifests reference are produced by the dev
PKI helper in the OutRelay main repo.
