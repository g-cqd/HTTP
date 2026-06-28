# Bench — consolidated comparative load battletest

End-to-end "vs the field" yardstick for the HTTP server. One runner (`run.sh`) drives our
`httpd-example` and every installed reference server with the **same** load generator (`oha`) across a
**set of route scenarios** on **identical** routes, and prints one throughput/tail-latency table per
scenario. It measures the whole socket-to-socket path — accept, parse, route, serialize, write.

This complements the in-package microbenchmarks (`swift package --package-path Benchmarking/Benchmarks
benchmark`), which lock per-engine **instructions** and **mallocs/op**; this harness is the wall-clock,
many-servers comparison. A representative run is recorded in [`RESULTS.md`](RESULTS.md).

> **Iron Law.** Optimize only what you can measure; prove every change with a second measurement.
> Report **percentiles, not averages** (the p99/p99.9 tail is what users feel), run in **release**, pin
> the workload, and run on a **quiet** machine (absolute rps is contention-sensitive — see caveats).

## Quick start

```sh
brew install oha jq                 # required: load generator + JSON parser
./Benchmarking/Bench/run.sh         # every installed server, all scenarios, 64 conns, 10s each
```

It works with only `ours` present; each other competitor is run if its toolchain/binary is installed,
and skipped (with a note) otherwise. Raw `oha` JSON + each server's log land in
`Benchmarking/Bench/results/` (git-ignored).

## Competitors

| server | role | install | port |
|---|---|---|---|
| **ours** (`httpd-example`) | the subject (built `-c release` at the current tree) | this repo | 8080 |
| **nginx** | C throughput/latency ceiling | `brew install nginx` | 8081 |
| **caddy** | modern Go server (h1/h2/h3) | `brew install caddy` | 8082 |
| **hummingbird** | SwiftNIO framework — "are we competitive without NIO?" | `Bench/hummingbird/` (SwiftPM, auto-built) | 8083 |
| **go** | Go `net/http` stdlib | `brew install go` | 8084 |
| **bun** | `Bun.serve` native server | `brew install oven-sh/bun/bun` | 8085 |
| **rust** | `hyper` + `tokio` (release) | `brew install rust` | 8086 |
| **vapor** | SwiftNIO framework | `Bench/vapor/` (SwiftPM, auto-built) | 8088 |
| **django-wsgi** | Django sync views under gunicorn, workers = cores | `Bench/django/` (auto venv) | 8087 |
| **django-asgi** | Django async views under uvicorn, workers = cores | `Bench/django/` (auto venv) | 8087 |

The two SwiftNIO packages (hummingbird, vapor) are nested in this repo, which SwiftPM mis-resolves
("product not found") — so the harness copies each **outside the repo tree** to build it, and reuses the
build until its sources change. The Django venv is created and `pip install`-ed on first run.

## Scenarios (the shared parity route set)

Every programmable server implements the same routes, so each scenario is an identical workload:

| scenario | exercises |
|---|---|
| `GET /` | framework floor (tiny text) |
| `GET /json` | serialize `{"message":"Hello, World!"}` |
| `GET /payload` | ~1 KiB compressible body |
| `GET /hello/world` | router + path/query parameter |
| `POST /echo` | request read + body round-trip |

nginx and caddy are static servers: they serve `/`, `/json`, `/payload`, `/hello`, but **cannot echo a
POST body** without a scripting module — so `POST /echo` shows **N/A** for them. The harness marks any
cell N/A when fewer than 99% of responses are 2xx (a server 404-ing a route it lacks).

## Knobs (env vars)

| var | default | meaning |
|---|---|---|
| `SERVERS` | all ten above | space-separated subset to run (present ones only) |
| `SCENARIOS` | `GET:/ GET:/json GET:/payload GET:/hello/world POST:/echo` | `METHOD:PATH` tokens to drive |
| `CONNECTIONS` | `64` | concurrent connections (closed loop) |
| `DURATION` | `10s` | measured wall-clock per scenario |
| `WARMUP` | `2s` | throwaway pre-measurement pass; `0` skips it |
| `RATE` | _(unset)_ | per-connection request rate → **open loop**, coordinated-omission-free latency |
| `BACKBONE` | `swiftSystem` | ours' transport: `swiftSystem` \| `posixKqueue` \| `posixDispatch` \| `networkFramework` |
| `DJANGO_WORKERS` | CPU cores | gunicorn/uvicorn worker count |
| `ECHO_BODY` | `{"x":1}` | request body for `POST /echo` |

Examples:

```sh
# A subset of servers + scenarios:
SERVERS="ours rust go nginx" SCENARIOS="GET:/json POST:/echo" ./Benchmarking/Bench/run.sh

# Heavier load, longer measurement:
CONNECTIONS=128 DURATION=20s ./Benchmarking/Bench/run.sh

# Compare our four I/O backbones (same engine):
for b in swiftSystem posixKqueue posixDispatch networkFramework; do
  SERVERS=ours BACKBONE=$b ./Benchmarking/Bench/run.sh
done

# Open-loop, coordinated-omission-free tail latency at a fixed rate:
RATE=2000 SERVERS="ours nginx rust" ./Benchmarking/Bench/run.sh
```

## Methodology & caveats

- **Release only.** `httpd-example` and rust are built `-c release`; debug numbers are fiction.
- **Loopback.** Runs hit `127.0.0.1`, so the NIC is out of the picture — this isolates
  framing/IO/allocation cost. A NIC-bound run is a separate, machine-specific exercise.
- **Quiet box.** Absolute rps is contention-sensitive: a run taken while a second benchmark was active
  showed nginx/caddy depressed 2–5×. Trust the **within-run ranking** and back-to-back **before/after
  deltas**; for trustworthy absolutes, run with nothing else loading the machine.
- **Closed vs open loop.** Default is closed-loop (`-c N`, max throughput). For tail-latency claims set
  `RATE` for an open-loop run that doesn't hide queueing delay (coordinated omission).
- **N/A** means the route returned <99% 2xx (unimplemented) — not that the server failed.
- **Django on bleeding-edge Python** (3.14 here) is flaky: gunicorn/uvicorn `[standard]` (uvloop /
  httptools) may lack wheels and fall back to a slow/contended loop, or crash a scenario. Treat the
  faster of the two Django rows as representative.
- **Per-client cap.** Our default per-client connection cap (a single-IP DoS guard) trips on a loopback
  test; `run.sh` launches us with `HTTPD_MAX_CONN=1000000` and `HTTPD_QUIET=1` (no access-log print).
