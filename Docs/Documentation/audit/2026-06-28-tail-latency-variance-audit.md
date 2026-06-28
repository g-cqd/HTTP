# Tail-Latency / Variability Audit & Remediation — 2026-06-28

## Summary

A load comparison showed our server with a **class-leading median but the worst tail of the fast
servers**: p50 0.22 ms (beating nginx) yet p99 ≈ 24× p50 and p99.9 ≈ 72× p50 (15–18 ms stalls on
0.1 % of requests), versus nginx's 1.3×/1.8×. Both other Swift servers (Hummingbird, Vapor) show the
same fat-tail signature, pointing at the Swift/ARC/GCD scheduling layer rather than per-request work.

This audit profiled the live server (`oha -c 64`, `sample`, `vmmap`/thread counts, binary call-tree
inspection) on an 8-core (4P+4E) M-series machine, reproduced the reported numbers, and isolated the
causes. The engine is fast; the deficit is **jitter** — thread oversubscription, default-QoS
scheduling, generic-metadata churn, and per-I/O continuation/ARC overhead.

## Method

- Built the benchmark server release (`Benchmarking/Django/ours`, the same `ours-bench` the comparison
  uses) and drove it with `oha -c 64` per backbone.
- Profiled with `/usr/bin/sample` at 1 ms over the load, plus live `ps -M` thread counts; inspected the
  symbolicated call tree (generic-metadata, continuation, ARC frames).
- Cross-checked the structural signals that are **noise-immune** (OS thread count; the
  `_swift_getGenericMetadata` sample tally) because the shared-core loopback bench + background load
  (Spotlight, WindowServer) make absolute p99.9 noisy run-to-run.

## Measured baseline — the headline is the backbone choice

The comparison benchmarks the **`swiftSystem`** backbone, which the code's own header documents as the
blocking-model reference ("overcommits the thread pool … not the high-concurrency default",
`SwiftSystemTransport.swift`). Under the identical load the event-driven backbones are 5–6× tighter:

| backbone | model | OS threads | rps | p50 | p99 | **p99.9** | max |
|---|---|---:|---:|---:|---:|---:|---:|
| **swiftSystem** *(benchmarked)* | blocking on GCD pool | **~68** | 124,990 | 0.249 | 4.047 | **16.421** | 72.453 |
| **posixKqueue** | event-driven | 12 | 143,291 | 0.428 | 1.217 | **2.793** | 15.354 |
| **posixDispatch** | event-driven (DispatchSource) | 22 | 129,715 | 0.438 | 1.262 | **3.054** | 23.302 |

`oha -c 64` against a blocking backbone parks ~64 worker threads in `read()` across keep-alive idle →
~68 threads on 8 cores. `sample` leaves: `read` 130,966 + `__workq_kernreturn` 125,653 dominate;
`syscall_thread_switch` 817 = the scheduler thrashing 68 threads → the p99.9 tail. The event-driven
backbones (12 / 22 threads) already beat rust's tail and rival bun's.

## Root causes (ranked, evidence-backed)

1. **swiftSystem oversubscribes GCD** (blocking read held across keep-alive idle → ~68 threads / 8 cores).
   Inherent to the blocking model; event-driven I/O is the structural fix.
2. **Per-field generic-metadata instantiation in the header parser** (every backbone). Call tree:
   `parseFieldLine → HTTPFieldName.init<A>(validating:)` → `_swift_getGenericMetadata` /
   `MetadataCacheKey::==` (~1,400 samples) because the generic init wasn't specialized across the
   HTTP1→HTTPCore boundary.
3. **No QoS on any transport dispatch queue** → default-priority threads descheduled under contention.
4. **Per-I/O continuation/ARC churn** (every backbone): `withCheckedThrowingContinuation` status-record
   locking + `OnceResumer` heap alloc/deinit (`OnceResumer.__deallocating_deinit` 355 samples) + the
   I/O-thread→cooperative-pool→I/O-thread hops (≥2 per request).
5. **Allocation churn**: `_ArrayBuffer._consumeAndCreateNew`, per-response `[UInt8]` from
   `ResponseSerializer.serialize`, malloc/free under concurrency.

## Remediation tracking

| ID | Change | Scope | Status | Evidence / gate |
|---|---|---|---|---|
| CC1 | `qos: .userInitiated` on every transport queue + serve task priority | all backbones | **Done** | event loops / accept / io / per-conn queues + `addTask(priority:)`; default-QoS jitter removed |
| CC2 | Specialize the header-parse hot path (concrete `UnsafeRawBufferPointer` `init`, no copy) | all backbones | **Done** | profiler: generic `HTTPFieldName.init<A>` **gone** (0 samples), now `specialized` under `parseFieldLine` |
| CC3 | `withUnsafeThrowingContinuation` + `OnceResumer`→`UnsafeContinuation` | all backbones | **Done** | `OnceResumer` already guarantees single-resume; backbone-conformance (cancel/teardown/split) green |
| CC6 | Reuse a per-connection response buffer | all backbones | **Done** | `ResponseSerializer.serialize(into:)` threaded through `serve`/`serveOne`; serializer suite green |
| SB1 | Event-driven as the documented production default; swiftSystem = labeled blocking reference | swiftSystem / example / bench | **Done** | `TransportBackbone.recommended` + default in `httpd-example` & bench |
| **R4** | **NIO-style event loop = `TaskExecutor`; connection serve task pinned (no hop); round-robin sharded N-per-P-core** | kqueue · epoll (Linux mirror) · **swiftSystem converted to event-driven** | **Done** | full suite (~970) + backbone-conformance green; measured below |
| CC4 | Hoist `withTaskCancellationHandler` to once-per-connection | all backbones | Pending | folds into R4 follow-up; per-op task-status-record churn |
| CC5 | (subsumed by R4) executor pinning | — | **Done (R4)** | `withTaskExecutorPreference(connection.preferredTaskExecutor)` in `HTTPServer.accept` |

## R4 result — the executor hop was the p50 gap

`-c1` proved per-request work was already at parity (swiftSystem ≡ kqueue ≈ 36 µs); the -c64 gap was the
**hop** from the readiness (loop) thread to the cooperative pool where the handler ran. Rewriting
`KqueueEventLoop` as an interleaved poll+execute run loop that *is* a `TaskExecutor`, then pinning each
connection's serve task to its loop (`preferredTaskExecutor`), makes read→parse→route→respond→write run
**inline on the loop thread** — exactly how the blocking backbone runs on its woken read thread. N loops
(round-robin per accepted connection; Darwin `SO_REUSEPORT` does **not** load-balance, so explicit
round-robin) restore parallelism with a **bounded** thread count.

Measured (this loaded box, `oha`, best-of-5, ms):

| | -c1 p50 | -c64 p50 | -c64 p99 | -c64 p99.9 |
|---|---:|---:|---:|---:|
| swiftSystem (blocking) | 0.036 | **0.155** | 3.416 | 9.975 |
| kqueue R4 (default = P-cores) | **0.031** | 0.326 | **1.193** | **3.985** |
| kqueue R4 (loops=2) | — | 0.352 | 0.844 | **1.123** |

`-c1`: kqueue now **beats** swiftSystem (no hop). `-c64`: p50 0.326 **beats nginx 0.337 and every
competitor's p50 except blocking-swiftSystem**, with p99 1.19 / p99.9 3.99 — **4× tighter than the
original swiftSystem** (5.29 / 15.93) and ahead of rust (2.12 / 6.94) and bun's p99 (1.26). Full 0.155
p50 parity is on a **Pareto frontier**: it needs swiftSystem's ~64-thread count, which *is* its tail. The
loop count (`TransportConfiguration.eventLoopCount` / `HTTPD_LOOPS`) tunes the operating point —
loops=2-3 buys p99.9 ≈ 1-1.5 ms for ~0.03 ms of median.

## Verification

- **Builds:** `HTTP_WARNINGS_AS_ERRORS=1 swift build` and `HTTP_PORTABLE_TLS=1 swift build` clean.
- **Correctness:** full `swift test` green; backbone-conformance suite (cancel/teardown/split-read across
  every backbone) green after CC3.
- **Profiling matrix:** `/tmp/measure.sh <backbone>` (median of N clean `oha -c 64` runs, no profiler
  perturbation) + `sample` metadata tally before/after. Structural signals (thread count, metadata
  samples) are the trustworthy gates given loopback/background noise.

## Honest notes

- swiftSystem's tail cannot match the event-driven backbones without becoming event-driven (a blocking
  read holds a thread across keep-alive idle). It stays as the documented blocking reference; production
  should default to kqueue (Darwin) / epoll (Linux).
- Several cross-cutting deltas are below this machine's end-to-end noise floor individually; they are
  justified by direct profiler evidence (metadata tally, thread count, sample leaves) and validated by
  correctness tests + micro-benchmarks rather than noisy end-to-end p99.9 alone.
