# Performance Battletest — 2026-06-25

A measured comparison of the server against the fastest HTTP servers available, and the before/after
record of the performance work, assessed through the **Iron Law** (cost = instructions × CPI ×
allocations, not wall-clock alone). It complements the security-focused
`2026-06-25-deep-hardening-audit.md`: this document is about throughput, tail latency, and allocation.

> **Iron-Law discipline.** No optimization was merged without (a) a measurement showing the bottleneck
> and (b) a second proving the fix. Two candidate optimizations were *refuted* by measurement before
> any code was written (§4) — the discipline's most valuable outcome.

## 1. Method

- **Harness:** `Benchmarking/Bench/run.sh` (oha-driven) drives `httpd-example` and the reference servers on identical
  routes, reporting rps + p50/p99/p99.9. Reproduce with `./Benchmarking/Bench/run.sh` (see `Benchmarking/Bench/README.md`).
- **Yardsticks:** **nginx** (the C throughput/latency ceiling), **Caddy** (modern Go, native h3),
  **Hummingbird** (the in-language SwiftNIO baseline — "are we competitive without NIO?").
- **In-package micro-metrics:** ordo-one `package-benchmark` captures `instructions` + `mallocCountTotal`
  per engine path; the test suite's `expectAllocations` (libmalloc hook) pins exact per-op allocations.
- **Environment:** Apple Silicon, macOS, loopback, release build, HTTP/1.1 cleartext. Numbers are
  machine-specific; the **relative** comparisons (vs the yardsticks, and before/after a change) are the
  durable findings. Loopback isolates framing/IO/allocation cost — it excludes NIC and TLS-handshake
  time, where a different profile applies.

## 2. Headline — the full matrix (single-sitting, loopback, 64 conns, warm 2 s + 8 s)

Every one of our backbones and HTTP-version variants against nginx + Caddy, captured **in one thermal
sitting** so the cross-server comparison is apples-to-apples (the run-to-run *absolutes* still drift on a
laptop — §7 — so read the **rankings**, not the digits). Reproduce: `BACKBONE=<b> ./Benchmarking/Bench/run.sh` and
`HTTP2=1 ./Benchmarking/Bench/run.sh`.

### HTTP/1.1 cleartext

| server / backbone | rps | p50 | p99 | p99.9 |
|---|---:|---:|---:|---:|
| nginx | **157k** | 0.38 ms | **0.82 ms** | **1.5 ms** |
| **ours** `swiftSystem` | **133k** | 0.23 ms | 6.3 ms | 18.6 ms |
| Caddy | 128k | 0.36 ms | 2.9 ms | 5.5 ms |
| **ours** `posixKqueue` | 128k | 0.46 ms | **1.2 ms** | 3.4 ms |
| **ours** `posixDispatch` | 115k | 0.52 ms | 1.2 ms | 2.6 ms |
| **ours** `networkFramework` | 84k | 0.68 ms | 1.7 ms | **2.5 ms** |

### HTTP/2 over TLS (ALPN; ours = `networkFramework`, the only TLS backbone)

| server | rps | p50 | p99 | p99.9 |
|---|---:|---:|---:|---:|
| nginx | **112k** | 0.55 ms | **0.82 ms** | **1.3 ms** |
| Caddy | 65k | 0.70 ms | 4.8 ms | 10.2 ms |
| **ours** (`networkFramework`+TLS) | 55k | 0.98 ms | **1.9 ms** | **2.5 ms** |

### HTTP/3 and Hummingbird — measured where the tooling allows

- **HTTP/3:** nginx (`--with-http_v3_module`) and Caddy (native) both *serve* h3, but **no h3 load client
  exists in this environment** — `oha`, `h2load` (absent), and this `curl` (SecureTransport) all lack
  HTTP/3. The end-to-end h3 throughput comparison is therefore blocked on *client* tooling, **not on our
  server.** Our h3 cost is characterized at the engine level (the in-tree HTTP/3 + QPACK benchmarks — §5
  alloc figures) and validated by the h3/QPACK conformance + fuzz suites. *Open tooling item: a
  ngtcp2-built `h2load` or an h3-enabled `curl`.*
- **Hummingbird (in-language NIO baseline):** still unbuildable here — `swift package resolve` silently
  no-ops on the `hummingbird` dependency in this SDK/toolchain (GitHub is reachable, so it is not a
  network fault), producing no `Package.resolved`. Harness config (`Benchmarking/Bench/hummingbird/`) is committed for
  a working toolchain. *Open tooling item.*

**Result (the durable rankings):** nginx is the throughput **and** tail leader on both protocols — the C
ceiling, as expected. Against **Caddy** we are competitive: on h1 our `swiftSystem` edges its throughput
(133k vs 128k) and `posixKqueue` matches it with a markedly tighter tail (p99.9 3.4 vs 5.5 ms); on h2 we
trail its throughput (55k vs 65k) but **own the tail by ~4×** (p99.9 2.5 vs 10.2 ms). The consistent
signature across the whole matrix: **we trade peak throughput for tail discipline** — our `posixKqueue`
(h1) and `networkFramework` (h2) hold the tightest non-nginx tails. Our h1 throughput reaches ~82–85 % of
nginx; the wider h2 gap (~49 %) is explained by known engine debt — h2-over-TLS must use the
`networkFramework` backbone (already the h1 laggard at 84k) and then pays TLS + HPACK + a per-response
HPACK field-block rebuild (the h2 analog of the h3 encode just optimized in §5), not transport contention.

## 3. The proven win — TCP_NODELAY on every backbone

Nagle's algorithm was never disabled (audit T-F14): a sub-MSS response could wait on the delayed-ACK
coalesce window, inflating the tail. Setting `TCP_NODELAY` (POSIX `setsockopt`) and
`NWProtocolTCP.Options.noDelay` (Network.framework) on every connection, measured before → after via
the harness (two passes):

| backbone | rps | p99.9 |
|---|---|---|
| **posixKqueue** | 108k → **~134k (+24 %)** | 5.1 → **2.8 ms (−45 %)** |
| **posixDispatch** | 98k → **~118k (+20 %)** | 4.2 → **2.1 ms (−50 %)** |
| networkFramework | 82k → 89k (+9 %) | 3.5 → 2.3 ms (−34 %) |
| swiftSystem | 131k → 138k (+6 %) | 19.5 → 17 ms (−13 %) |

The async backbones gained most — Nagle was holding their batched small writes. This re-ranked us
from "fat-tail outlier" to "competitive with nginx."

## 4. Iron-Law refutations (optimizations the data killed)

- **SWAR `memchr` in `ByteReader.firstIndex`** — A/B-benchmarked and **rejected**: the scalar scan wins
  for the short delimiters the HTTP/1 parser actually searches. Documented at `ByteReader.swift`.
- **Sharding the single-threaded kqueue event loop (audit B2)** — the premise ("one serial queue can't
  scale") was **refuted**: at 256 and 512 connections `posixKqueue` *leads* the concurrent-queue
  `posixDispatch` (141k/140k vs 127k/124k). The single queue only dispatches cheap readiness events
  (`kevent` poll + continuation resume); request processing already runs on the multi-core Swift
  concurrency pool via per-connection tasks. Sharding would have added real concurrency complexity for
  ~0 gain. **Not done.**

| backbone | 64 conns | 256 conns | 512 conns |
|---|---:|---:|---:|
| posixKqueue | 134k | 141k | 140k |
| posixDispatch | 118k | 127k | 124k |
| swiftSystem | 138k | 146k | 138k |
| networkFramework | 89k | 86k | 81k |

(The networkFramework laggard is its abstraction/copy overhead, not a contention limit; it is the TLS
backbone, not the cleartext throughput path. A true zero-copy NF receive is unsafe today — the async
`send` would let a `bytesNoCopy` pointer escape its scope — so it is left for a profiled follow-up.)

## 5. Allocation baselines (the per-request cost toward 200k rps)

The gap to the 200k-rps north star is per-request work, not transport. Engine allocation baselines,
now measured and gate-locked:

| path | allocations / op | guard |
|---|---:|---|
| QPACK decode (7-field request) | **6** | `expectAllocations` (CI, deterministic) |
| `Date` header, warm same-second | **0** | per-second `DateCache` + `expectAllocations` |
| HTTP/3 `FrameDecoder.nextFrame` | 1 | eager `Array(payload)` copy — P2 target |
| HTTP/3 `Connection` receive-get | 24 | decode 6 + owned-request map 17 + frame copy 1 — near floor, deferred |
| HTTP/3 `Connection` respond | **11** (was 32) | borrow-encode into a reserved buffer — done, gate-locked |

## 6. Locking the wins

- **Allocation ceilings** via `expectAllocations` (libmalloc hook) run in the normal `swift test` CI
  gate — deterministic and machine-independent (unlike wall-clock). New: QPACK decode ≤ 6, `DateCache`
  warm = 0.
- **Benchmark metric config** pins `instructions` + `mallocCountTotal` for `swift package benchmark
  baseline compare`. (ordo's `thresholds check --check-absolute` is unusable here — it writes
  underscored threshold filenames but reads the slash-grouped benchmark names, so it never matches;
  `expectAllocations` + `baseline compare` cover the same ground.)
- **Benchmark coverage** filled the HTTP/3 + QPACK columns (none existed) and the engine-level h3
  `receive`/`respond` paths.

## 7. Caveats & follow-ups

- Numbers are loopback + machine-specific; a NIC-bound and TLS-handshake profile is a separate exercise.
- **Absolutes are soft; rankings are firm.** On this (laptop) host, repeated runs of the *same* config
  swung up to ~3× in absolute rps with sustained-load thermal drift — so every absolute here is an
  order-of-magnitude anchor, not a precise figure. What reproduced across runs is the **within-run
  ranking** and the **before/after deltas** (both measured back-to-back under one thermal state). The
  harness now warms up before measuring (`WARMUP`, default 2 s) to drop the cold-handshake transient;
  a quiet, pinned host is still required for trustworthy tail absolutes.
- macOS lacks per-thread PMU counters; `instructions` from `ri_instructions` is coarse — use `xctrace`
  ('CPU Counters') or a Linux `perf stat` runner for precise CPI / cache-miss attribution.
- **Open perf items:** networkFramework zero-copy (needs profiling), the HTTP/3 per-frame eager copy, and
  the h3 **receive** per-field String allocations (the 24-malloc decode path). The h3 **respond** path is
  **done** (32 → 11, §5, gate-locked); the riskier decode-side borrow remains. The h2-over-TLS comparison
  is recorded (§2); the h3-over-TLS comparison and the Hummingbird baseline remain (tooling, not server).
