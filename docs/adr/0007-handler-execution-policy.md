# ADR 0007 — Handler execution policy (where application code runs)

- **Status:** Accepted, shipped at `.inline`. The default is **not** flipped by this ADR; see
  *Pre-registered decision rule* and *Measurement*.
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

Recorded separately, in the commit that took it. See the *Measurement* section appended below.

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
