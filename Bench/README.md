# Bench — comparative load battletest

End-to-end "vs the best" yardstick for the HTTP server. It drives our `httpd-example` and any
installed reference servers with the **same** load generator on **identical** routes, and reports
throughput (rps) and tail latency (p50/p99/p99.9) side by side.

This complements — it does not replace — the in-package microbenchmarks (`swift package
--package-path Benchmarks benchmark`), which lock per-engine **instructions** and **mallocs/op**.
This harness measures the whole socket-to-socket path: accept, parse, route, serialize, write.

> **Iron Law.** We optimize only what we can measure, and prove every change with a second
> measurement. Here that means: report **percentiles, not averages** (the p99/p99.9 tail is what
> users feel), run in **release**, pin the workload, and — when chasing latency — drive a
> **constant rate** (`RATE=…`) so the numbers are free of coordinated omission.

## Quick start

```sh
brew install oha            # required load generator (HTTP/1.1 + HTTP/2)
brew install jq             # optional, for parsed tables
./Bench/run.sh              # ours vs any installed reference servers, route / , 64 conns, 10s
```

Useful knobs (all env vars):

| var | default | meaning |
|---|---|---|
| `ROUTE` | `/` | path hit on every server (`/`, `/health`) |
| `CONNECTIONS` | `64` | concurrent connections (closed loop) |
| `DURATION` | `10s` | wall-clock per run |
| `RATE` | _(unset)_ | per-connection request rate → **open loop**, coordinated-omission-free latency |
| `BACKBONE` | `swiftSystem` | our transport: `swiftSystem` \| `posixKqueue` \| `posixDispatch` \| `networkFramework` |
| `SERVERS` | `ours nginx caddy hummingbird` | which to run (present ones only) |
| `HTTP2` | `0` | `1` adds `oha --http2` (needs TLS; cleartext h2c is not oha-drivable) |

Compare backbones (our four I/O strategies, same engine):

```sh
for b in swiftSystem posixKqueue posixDispatch networkFramework; do
  SERVERS=ours BACKBONE=$b ./Bench/run.sh
done
```

## Reference servers (the yardsticks)

| server | role | install | port |
|---|---|---|---|
| **ours** (`httpd-example`) | the subject | built from this repo (release) | 8080 |
| **Hummingbird** | in-language SwiftNIO baseline — "are we competitive without NIO?" | `Bench/hummingbird/` (SwiftPM) | 8083 |
| **nginx** | C throughput/latency ceiling | `brew install nginx` | 8081 |
| **Caddy** | modern Go, native h1/h2/h3 | `brew install caddy` | 8082 |

`run.sh` launches each present server on its port, mirrors the routes (`Bench/servers/*`), runs `oha`,
parses the JSON, and prints a markdown table. Missing servers are skipped with a note — so it works
with just `ours` out of the box.

## Methodology & caveats

- **Release only.** The harness builds `httpd-example` with `-c release`; debug numbers are fiction.
- **Loopback.** Runs hit `127.0.0.1`, so the NIC and TLS handshake are out of the picture — this
  isolates framing/IO/allocation cost. A NIC-bound run is a separate, machine-specific exercise.
- **Connection cap.** Our default per-client cap (20) is a single-IP DoS guard that a loopback test
  trips; `run.sh` launches us with `HTTPD_MAX_CONN=1000000`. Reference servers raise theirs too.
- **Closed vs open loop.** Default is closed-loop (`-c N`): max throughput. For tail-latency claims,
  set `RATE` for an open-loop run that doesn't hide queueing delay (coordinated omission).
- **h2 / h3.** `oha --http2` needs TLS; our h2c is prior-knowledge cleartext (curl can, oha can't).
  Run the TLS example (`swift run httpd-example 8443 networkFramework tls`) and point `oha --http2`
  at it for the h2 comparison; h3 needs an h3-capable client (e.g. a browser, or `h2load --npn h3`).
- **Warm up.** `oha -z` includes ramp; for tighter numbers raise `DURATION` and discard the first run.

Results (raw `oha` JSON + each server's stdout/stderr) land in `Bench/results/` (git-ignored).
