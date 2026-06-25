# Performance Battletest — 2026-06-25

A measured comparison of the server against the fastest HTTP servers available, and the before/after
record of the performance work, assessed through the **Iron Law** (cost = instructions × CPI ×
allocations, not wall-clock alone). It complements the security-focused
`2026-06-25-deep-hardening-audit.md`: this document is about throughput, tail latency, and allocation.

> **Iron-Law discipline.** No optimization was merged without (a) a measurement showing the bottleneck
> and (b) a second proving the fix. Two candidate optimizations were *refuted* by measurement before
> any code was written (§4) — the discipline's most valuable outcome.

## 1. Method

- **Harness:** `Bench/run.sh` (oha-driven) drives `httpd-example` and the reference servers on identical
  routes, reporting rps + p50/p99/p99.9. Reproduce with `./Bench/run.sh` (see `Bench/README.md`).
- **Yardsticks:** **nginx** (the C throughput/latency ceiling), **Caddy** (modern Go, native h3),
  **Hummingbird** (the in-language SwiftNIO baseline — "are we competitive without NIO?").
- **In-package micro-metrics:** ordo-one `package-benchmark` captures `instructions` + `mallocCountTotal`
  per engine path; the test suite's `expectAllocations` (libmalloc hook) pins exact per-op allocations.
- **Environment:** Apple Silicon, macOS, loopback, release build, HTTP/1.1 cleartext. Numbers are
  machine-specific; the **relative** comparisons (vs the yardsticks, and before/after a change) are the
  durable findings. Loopback isolates framing/IO/allocation cost — it excludes NIC and TLS-handshake
  time, where a different profile applies.

## 2. Headline — vs the best (HTTP/1.1, loopback, 64 connections)

| server | rps | p50 | p99 | p99.9 |
|---|---:|---:|---:|---:|
| **ours** (`posixKqueue`, post-fixes) | ~134k | 0.46 ms | **1.10 ms** | **2.80 ms** |
| **ours** (`swiftSystem`, post-fixes) | **~138k** | 0.23 ms | 6.2 ms | 17 ms |
| nginx | **162k** | 0.38 ms | **0.76 ms** | **1.35 ms** |
| Caddy | 128k | 0.32 ms | 3.4 ms | 6.3 ms |

**Result:** our best-balanced backbone (`posixKqueue`) **beats Caddy on both throughput and tail** and
reaches **~83 % of nginx's throughput** with a p99.9 within ~2× of nginx — competitive with the C
ceiling. `swiftSystem` has the highest throughput but a thread-per-connection tail. (Hummingbird/h2/h3
comparisons are pending a clean toolchain for the NIO build / a TLS load client; the harness supports
them.)

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
| HTTP/3 `Connection` receive-get | 24 | per-field `String`/`HeaderField` — P2 target |
| HTTP/3 `Connection` respond | 32 | `responseFields` rebuild — P2 target |

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
- macOS lacks per-thread PMU counters; `instructions` from `ri_instructions` is coarse — use `xctrace`
  ('CPU Counters') or a Linux `perf stat` runner for precise CPI / cache-miss attribution.
- **Open perf items:** networkFramework zero-copy (needs profiling), the HTTP/3 per-frame eager copy and
  per-field String allocations (the 24/32-malloc paths above), and the h2/h3-over-TLS comparison.
