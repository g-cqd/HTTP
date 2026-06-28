# Bench — consolidated comparative results

One harness (`run.sh`), one load generator (`oha`), identical route, side by side. This file records a
representative run; re-run `./Benchmarking/Bench/run.sh` to regenerate (raw `oha` JSON lands in
`results/`).

## Run: route `/`, 64 connections, 10s, HTTP/1.1 cleartext

Apple Silicon, 8 logical CPUs. Each server warmed 2s, then measured 10s closed-loop. `ours` on the
`swiftSystem` backbone. Sorted by throughput.

| server | rps | p50 (ms) | p99 (ms) | p99.9 (ms) | notes |
|---|---:|---:|---:|---:|---|
| rust (hyper + tokio) | 143,161 | 0.361 | 2.397 | 7.157 | release, multi-thread runtime |
| nginx | 130,268 | 0.380 | 1.680 | 7.347 | C, event-driven |
| **ours (swiftSystem)** | **125,357** | **0.232** | 6.113 | 17.647 | **best p50 of the field** |
| bun (Bun.serve) | 99,481 | 0.485 | 1.754 | 3.824 | tightest tail |
| caddy | 81,751 | 0.412 | 5.839 | 19.785 | Go production server |
| go (net/http) | 81,160 | 0.260 | 7.963 | 41.028 | stdlib |
| django-wsgi | 2,739 | 13.766 | 30.527 | 135.964 | gunicorn, sync, workers = cores |
| django-asgi | 1,603 | 224 | 9,142 | 9,151 | ⚠ anomalous — see caveats |
| hummingbird | — | — | — | — | ⚠ did not build — see caveats |

### Takeaways

- **We place third of the field and post the lowest median latency (p50 0.232 ms) of every server
  measured** — ahead of Bun, Caddy, Go, and Django; within ~14% of nginx and ~12% of hyper on rps.
- Our **tail** (p99 6.1 ms / p99.9 17.6 ms) is looser than rust/nginx/bun. That tail is the obvious
  optimization target — it lines up with the audit's P1 items (per-request allocation, the metrics
  handle churn) and is the natural subject for the next measure-first pass.
- Throughput ordering is the expected shape: a lean Rust/C event core on top, the compiled servers in
  a tight band, the Python framework two orders of magnitude back.

### Caveats (environment edges, not harness bugs)

- **hummingbird** fails to build on this toolchain (Xcode-beta, Swift 6.4 beta, macOS 27 SDK): its
  package manifest does not register the `Hummingbird` product under this beta `PackageDescription`
  evaluator (`product 'Hummingbird' … not found`), independent of any SwiftPM cache state. Re-runs on a
  released Swift toolchain, or a pinned compatible hummingbird tag, should restore it. The build log is
  captured at `results/hummingbird.build.log`.
- **django-asgi** shows a pathological tail (p99 ≈ 9 s) — uvicorn's `[standard]` fast path (uvloop /
  httptools) has no wheels for the very new Python 3.14 here, so it falls back to a slow/contended
  asyncio loop. **`django-wsgi` (gunicorn, 2,739 rps) is the representative Django number**; treat the
  ASGI row as unreliable until run on a Python with uvloop/httptools support.

## Reproduce

```sh
./Benchmarking/Bench/run.sh                                  # all present servers, route / , 64c, 10s
SERVERS="ours rust nginx go bun" DURATION=20s ./Benchmarking/Bench/run.sh
ROUTE=/health CONNECTIONS=128 ./Benchmarking/Bench/run.sh
HTTP2=1 SERVERS="ours nginx caddy" ./Benchmarking/Bench/run.sh   # h2-over-TLS subset
```

The per-engine **instructions / mallocs-per-op** microbenchmarks (a different, allocation-level lens)
live in `Benchmarking/Benchmarks/` and are run with
`swift package --package-path Benchmarking/Benchmarks benchmark`.
