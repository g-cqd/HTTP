# ADR 0007 — Handler execution policy (where application code runs)

- **Status:** Accepted, shipped at `.inline`. The default is **not** flipped by this ADR: the
  pre-registered rule fired on its throughput clause (−6.01 % against a −5 % bar), and the
  measurement is explicitly provisional. See *Pre-registered decision rule* and *Measurement*.
- **Context date:** 2026-08

## Context

`HTTPServer.accept(_:)` wraps a connection's **entire** structured serve hierarchy:

```swift
await withTaskExecutorPreference(connection.preferredTaskExecutor) {
    await serve(connection)
}
```

Swift's executor-preference semantics apply that preference to every child task of the hierarchy —
Apple's documentation for `withTaskExecutorPreference(_:isolation:operation:)` states the preferred
executor "will be used whenever possible, rather than hopping to the global concurrent pool", and the
worked example in that page shows the preference being inherited by `async let` and task-group
children alike.

`preferredTaskExecutor` is non-nil on four backbones — `POSIXKqueueConnection`,
`POSIXEpollConnection`, `PortableTLSConnection`, `SwiftSystemConnection` — and on all four it is the
**serial** event loop. So routing, middleware, handlers, filesystem calls, compression, cryptography,
logging and streaming producers can all run on one reactor thread.

Two consequences, both raised by the 2026-07-31 codebase review as finding 7 and escalated by the
performance addendum under "Execution topology is the largest throughput ceiling":

1. CPU-heavy handlers on one HTTP/2 connection cannot use more than one core. Adding connection tasks
   produces no parallelism when they all run on the same serial executor.
2. One blocking handler stalls **every** connection sharded onto that loop (CWE-410).

The second is not a projection. `HandlerExecutionIsolationTests` puts two loopback connections on one
event loop (`TransportConfiguration(eventLoopCount: 1)`), blocks connection A's handler on a
`ThreadGate`, and then asks connection B for a trivial route. Under `.concurrent` B is answered in
33 ms. Under `.inline` B's socket returns an **empty read** for the whole 20-second receive timeout:
its readiness is never processed at all, because the one reactor thread is inside A's handler.

This was also the topology that *won* the trivial-route benchmark, which is exactly why it needs a
recorded decision rather than a preference. Removing the executor hop is a real median-latency win on
a route that does nothing (audit R4, the change that introduced the wrap); the question is what it
costs everything else.

## Decision

Add `HandlerExecutionPolicy` as an `HTTPServer` initializer parameter, **defaulting to `.inline`**:

```swift
public enum HandlerExecutionPolicy: Sendable, Equatable {
    case inline
    case concurrent
    case adaptive(threshold: Duration)
}
```

It is on the designated initializer and on the `ContinuousClock` convenience initializer.

**Not an `HTTPLimits` knob.** `HTTPLimits` documents itself as engine *resource limits*, is immutable
and range-validated, and every one of its fields bounds something an adversary can grow. "Which
executor does application code run on" bounds nothing; it is a topology choice.

**The top-level wrap does not change.** The reactor keeps readiness, parsing, protocol state and
socket I/O for the connection's whole life — the single-owner invariant every engine is built on.
Only the handler subtree is lifted, at the six `respond` seams:

| Seam | File | Path |
|---|---|---|
| 1 | `HTTPServer+RequestReader.swift` | HTTP/1.1 buffered |
| 2 | `HTTPServer+RequestStreaming.swift` | HTTP/1.1 streaming |
| 3 | `HTTPServer+HTTP2RequestStreaming.swift` | HTTP/2 buffered dispatch |
| 4 | `HTTPServer+HTTP2RequestStreaming.swift` | HTTP/2 streaming-route head |
| 5 | `HTTPServer+HTTP3.swift` | HTTP/3 buffered |
| 6 | `HTTPServer+HTTP3Streaming.swift` | HTTP/3 streaming |

All six route through one function, `HTTPServer.respond(to:body:context:following:)`.

### Correction: the real exposure was three seams, not six

The finding describes the preference as reaching every handler. Measured on this toolchain, it does
not, and the difference is invisible from the call sites:

```
enclosing task:      serial.probe
async let child:     serial.probe          ← inherits
group child:         serial.probe          ← inherits
Task { }:            com.apple.root.default-qos.cooperative   ← does NOT inherit
Task.detached { }:   com.apple.root.default-qos.cooperative   ← does NOT inherit
```

Seams 4 and 6 each dispatch through an unstructured `Task` — it exists so a peer `RST_STREAM` has a
handle to cancel (audit finding 6) — so those handlers were **already** off the reactor. HTTP/3 has
no preference at all in the first place: `runHTTP3()` is not wrapped, because a QUIC connection is
not a `TransportConnection` and has no event loop to prefer, so seams 5 and 6 were never pinned.

The seams that genuinely sat on a serial reactor were **HTTP/1.1 buffered, HTTP/1.1 streaming, and
HTTP/2 buffered dispatch**. All six route through the policy regardless, so the guarantee is uniform
rather than an accident of how each task happens to be created — and
`HandlerExecutionReactorAffinityTests` pins the asymmetry, so turning either unstructured `Task` into
a structured child cannot silently re-expose it.

### The hop is `globalConcurrentExecutor`, not `nil`

This is load-bearing and easy to get backwards. Apple documents the `nil` argument to
`withTaskExecutorPreference` as "no preference and calling this method will have no impact on
execution semantics of the operation" — it does **not** clear an inherited preference. (The page also
contains a "Disabling task executor preference" paragraph that says `nil` disables the preference;
the parameter documentation and the worked example, which uses `globalConcurrentExecutor` to disable
an outer preference, are the ones that match the shipped stdlib.)

Verified empirically on this toolchain (Apple Swift 6.4) with a probe binary that reports the dispatch
queue label under an outer serial preference:

```
outer:                  serial.probe
inner nil:              serial.probe          ← no-op
inner globalConcurrent: com.apple.root.default-qos.cooperative
back outer:             serial.probe          ← the preference is restored on return
```

The restore in the last line is what puts the response write back on the owning reactor.

### No lock is added

The audit's constraint was that no lock may guard reactor-owned connection, parse or protocol state.
None is:

- **HTTP/1.1** parse state (`buffer`, `start`, `responseBuffer`) stays `inout` locals of the
  reactor-pinned keep-alive loop and is never captured by a hopped closure. The hop takes owned
  values (`HTTPRequest`, `RequestBody`, `RequestContext`) and returns one owned `ServerResponse`.
- **HTTP/2** needed no new machinery: `.requestReady(streamID, response)` was *already* the
  return-to-owner mechanism, so HPACK state, flow-control windows and `connection.send` keep their
  single owner regardless of which executor ran the handler.
- **HTTP/3** was verified rather than assumed, because its dispatcher routes engine output by stream
  id and does **not** funnel writes through a single consumer the way HTTP/2 does. It is safe for a
  different reason: the engine is an actor, and each response is written to its own QUIC stream,
  which RFC 9000 §2 makes independent. No cross-stream wire order depends on the calling task's
  executor, and per-stream order is the serving task's own statement order.

`.adaptive` does keep shared per-route statistics, which cannot be single-owner by definition. Those
use the package's existing `SharedBoundedLRU`/`ShardedMutex` primitive, are touched only on the
opt-in adaptive path, and the lock is never held across an `await`.

### Ordering

RFC 9112 §9.3 requires a server to send pipelined HTTP/1.1 responses in request order, and there is
no response identifier on the wire to recover it. Order is preserved structurally, not by new
machinery: `serveOne` is one sequential statement of `serveBody`'s `while` loop, the hop is scoped to
the `respond` call, the serialize-and-`send` runs after it returns, and the next request is not read
until `serveOne` returns. `HandlerExecutionOrderingTests` proves it adversarially — four pipelined
requests with **descending** handler delays (40/30/20/10 ms), so any design that dispatched them
concurrently would emit them in exactly the inverse order.

### `.adaptive`

Per matched route, using seams that already exist (`MonotonicNowProvider`, `RollingWindow`,
`SharedBoundedLRU`), so it adds no timing infrastructure and inherits a deterministic test clock:

> A route hops when the **previous** evaluation window (1 s) contained a handler run longer than the
> threshold, or when the **current** window has already seen one. A route with no measurement runs
> inline.

The first clause is deliberate hysteresis: without it one fast request erases the evidence of a slow
one and a route flaps between executors request by request, which costs more than either decision.

Keyed on `RouteMatch.Handle` (router identity + table index), never on the request path — a
parameterized route keyed by path would mint one bucket per URL, which is unbounded and
attacker-chosen (CWE-770). Matches from a `RouteResolver` that mints no handle share one bucket.

## Pre-registered decision rule

**Recorded before any measurement was taken, so the verdict cannot be retrofitted to the numbers.**
This is the same discipline as `Benchmarking/Benchmarks/Benchmarks/HTTPBenchmarks/RoutingBenchmarks.swift`,
which records its rule in the file header and then declines to build the thing it was considering.

> Adopt `.concurrent` as the default **only if all three hold**:
>
> 1. trivial-route **p50 regresses by less than 10 %**, and
> 2. trivial-route **throughput regresses by less than 5 %**, and
> 3. a **90/10 trivial + blocking mix improves trivial-route p99 by more than 2×**.
>
> If trivial p50 regresses by **10 % or more**, evaluate `.adaptive` against the same three clauses
> instead.
>
> If neither passes, **`.inline` stays the default** and this ADR records the number that decided it.

Rationale for those bars. Clause 1 and 2 are the cost side: the hop is paid by every request,
including the overwhelming majority that are trivial, and the reason the current topology exists at
all is that it won exactly this case. Clause 3 is the benefit side, and it is set at 2× rather than
something marginal because the failure mode is not a slow tail — it is a *stalled shard*, which
should show up as a difference of kind, not of degree. A 90/10 mix is a deliberately conservative
model of "most requests are cheap and a few are not"; a heavier blocking share would make
`.concurrent` look better and prove less.

Workload, fixed with the rule:

- `GET /exec/trivial` — a tiny text body; the cost of the policy and nothing else.
- `GET /exec/cpu` — ~2 ms of real arithmetic, iteration count calibrated **once** and pinned.
- `GET /exec/block` — `Thread.sleep` for 10 ms, holding a thread rather than suspending a task.

All three live in `Sources/Examples/httpd-example/ExecutionTopology.swift` behind
`HTTPD_EXEC_ROUTES=1`, so the five-route parity set that `Benchmarking/Bench/run.sh` compares against
nginx, caddy, Go, Bun, Rust, Hummingbird, Vapor and Django is byte-identical when the flag is unset.
`HTTPD_HANDLER_EXEC=inline|concurrent|adaptive[:ms]` selects the policy.

## Measurement

### This measurement is PROVISIONAL and does not decide the default

The host had been running concurrent agent workloads throughout this work. **No number below is
decision-grade**, and the default is not flipped on this evidence. What follows is a record of what
was measured, under what conditions, and what an idle-host run would have to show.

Two runs were taken. Their disagreement is the most important thing in this section.

| | run 1 | run 2 |
|---|---|---|
| load average at start | 14.17 | 6.30 |
| concurrent interference | three `swift-frontend` at 50–90 % (this branch's own test compiles) | none of ours; `coreaudiod` at ~100 % throughout both |
| `inline`/trivial rps across 3 rounds | 31,438 / 37,216 / 56,472 — a **1.80× spread** | 57,443 / 57,676 / 58,444 — a **1.02× spread** |
| clause 3 verdict | 1.04× — fails | 2.28× — passes |

The same configuration produced a 1.8× throughput spread across three consecutive rounds in run 1.
A benchmark that cannot reproduce itself within 80 % cannot adjudicate a 5 % clause. Run 2 is
reported below because its round-to-round spread is under 2 %, but "internally consistent" is not
"decision-grade": both runs shared a host with a process pinning a core the entire time.

### Run 2 — best of 3, `posixKqueue`, 64 connections, 10 s, 2 s warmup, 2026-08-01

Darwin 27.0.0 arm64, 10 logical cores (6P + 4E), release build, load average 6.30 at start.

**trivial route alone**

| policy | rps | p50 (ms) | p99 (ms) | p99.9 (ms) |
|---|---:|---:|---:|---:|
| inline | 58,444 | 0.891 | 4.691 | 8.371 |
| concurrent | 54,929 | 0.878 | 5.539 | 9.359 |
| adaptive:1 | 53,512 | 1.008 | 3.866 | 5.856 |

**90/10 trivial + blocking mix** (90 connections on `/exec/trivial`, 10 held in `/exec/block`)

| policy | rps | p50 (ms) | p99 (ms) | p99.9 (ms) |
|---|---:|---:|---:|---:|
| inline | 5,367 | 15.646 | 33.082 | 38.213 |
| concurrent | 14,965 | 2.588 | 14.490 | 15.234 |
| adaptive:1 | 15,373 | 2.546 | 14.398 | 15.109 |

**CPU route alone** (~1.8 ms of arithmetic; reported for attribution, not gated by the rule)

| policy | rps | p50 (ms) | p99 (ms) | p99.9 (ms) |
|---|---:|---:|---:|---:|
| inline | 2,496 | 25.869 | 28.648 | 32.491 |
| concurrent | 3,073 | 20.442 | 31.685 | 57.983 |
| adaptive:1 | 3,098 | 20.332 | 30.523 | 46.553 |

### Verdict against the pre-registered rule

| clause | bar | `.concurrent` | result |
|---|---|---|---|
| 1 — trivial p50 | regression < 10 % | **−1.46 %** (0.891 → 0.878 ms; an improvement) | **pass** |
| 2 — trivial throughput | regression < 5 % | **−6.01 %** (58,444 → 54,929 rps) | **fail** |
| 3 — mix trivial p99 | improvement > 2× | **2.28×** (33.082 → 14.490 ms) | **pass** |

**`.inline` stays the default.** Clause 2 fails by roughly one percentage point.

`.adaptive(threshold: 1 ms)` is not rescued by the fallback branch — that branch is only reached when
trivial p50 regresses by 10 % or more, which it did not — and it would fail anyway: p50 **+13.13 %**
(clause 1) and throughput **−8.44 %** (clause 2). Its throughput cost on a trivial route is the price
of the bookkeeping itself: two monotonic clock reads and two sharded-mutex acquisitions per request,
on a route whose whole service time is under a millisecond. It buys nothing there, because a trivial
route never crosses the threshold and so never hops.

### What the numbers say beyond the rule

The finding reproduces, and it is not subtle. Under the 90/10 mix, `.inline` serves the trivial route
at **5,367 rps with a 15.6 ms median**, while `.concurrent` serves it at **14,965 rps with a 2.6 ms
median** — 2.79× the throughput and 6.05× the median. Ten connections parked in a 10 ms handler cost
`.inline` 91 % of its trivial-route throughput.

Two things temper it, and both are why the rule was written the way it was:

1. **`.inline` is already parallel across shards.** With the default `eventLoopCount` (one loop per
   core), ten reactors run concurrently; what serializes is the connections *within* one shard. That
   is why the CPU route gains only 23 % (2,496 → 3,073 rps) rather than a multiple: it was already
   using every core. The blocking case is dramatic and the CPU case is modest, and both are correct.
2. **`.concurrent` relocates the blocking damage, it does not remove it.** The mix p99 improves 2.28×
   but not 10×, because ten threads held for 10 ms are ten threads held for 10 ms wherever they live.
   Moving them off the reactors keeps readiness, parsing and writes flowing, which is what the median
   shows; it does not create thread capacity.

The trivial-route cost of `.concurrent` is real but small: p50 is actually *lower* (0.878 vs
0.891 ms), while throughput is 6 % down. That shape is consistent with the hop costing scheduling
overhead per request without adding latency to any individual one.

### What an idle-host run would have to show

To flip the default to `.concurrent`, a controlled run — quiesced machine, no other tenant above a
few percent, ROUNDS ≥ 5, and a reported round-to-round spread under 5 % — would have to show
trivial-route throughput within 5 % of `.inline` while keeping clause 3. Clause 2 is the only one
currently failing and it fails by about one point, which is inside the noise band of even the good
run here. That is precisely why it needs an idle host rather than a re-reading of these numbers.

If a controlled run reproduces a 6 % trivial-throughput cost, the honest conclusion is not
"`.concurrent` anyway" but that the default should stay `.inline` and `.concurrent` should be
documented as the setting for deployments whose handlers do real work — which is what it is today.

### Reproducing

`Benchmarking/Bench/handler-execution.sh` (defaults: `DURATION=10s CONNECTIONS=64 ROUNDS=3
MIX_TRIVIAL=90 MIX_BLOCKING=10 POLICIES="inline concurrent adaptive:1"`). It records host
qualification alongside the results. Raw `oha` JSON lands under `Benchmarking/Bench/results/`, which
is gitignored, so this ADR is the record.

Two caveats about the harness itself, since they bound what it can claim. Best-of-N **selects
favorable noise** rather than estimating a distribution; it is used here because `run.sh` uses it and
comparability mattered more than rigor. And best-of-N is taken on **throughput**, so the p99 in each
row is the p99 *of the highest-throughput round* — which is not the same as the best p99, and is a
latent inconsistency in the pre-registered rule that clause 3 depends on. In run 2 the choice does
not matter (p99 varies by under 1 % across rounds). In run 1 it changes clause 3 from 1.04× to 2.27×,
which is a second, independent reason run 1 decides nothing.

## Consequences

- The default is unchanged, so no deployment changes behavior on upgrade.
- Every policy serves an identical response on every protocol and both body modes; that invariant is
  parameterized over {`.inline`, `.concurrent`, `.adaptive`} × {h1 buffered, h1 streaming, h2, h3} in
  `HandlerExecutionParityTests`.
- `.concurrent` costs one executor hop per request in each direction. On a backbone with no preferred
  executor (the in-memory fakes, Network.framework) the hop is between the cooperative pool and
  itself, and is close to free but not free.
- `.concurrent` does not make a blocking handler harmless — it relocates the damage from a reactor
  shard to a cooperative-pool thread. Hard isolation from hostile code needs a process boundary, as
  the audit's finding 17 already records for `TimeoutMiddleware`.
- New public API: `HandlerExecutionPolicy` and two defaulted initializer parameters. Additive and
  source-compatible; nothing was removed or renamed.
