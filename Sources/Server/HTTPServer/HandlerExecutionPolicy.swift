//
//  HandlerExecutionPolicy.swift
//  HTTPServer
//
//  Where an application handler runs relative to the connection's I/O reactor (2026-07-31 audit,
//  CR-F7 "Application handlers run on serial I/O executors"; performance addendum, "Execution
//  topology is the largest throughput ceiling").
//
//  ``HTTPServer`` wraps a connection's ENTIRE structured serve hierarchy in
//  `withTaskExecutorPreference(connection.preferredTaskExecutor)`, and Swift's executor-preference
//  semantics apply that preference to every child task of the hierarchy — Apple's documentation for
//  `withTaskExecutorPreference(_:isolation:operation:)` is explicit that the preferred executor "will
//  be used whenever possible, rather than hopping to the global concurrent pool", including for child
//  tasks. On the four loop-backed backbones (`POSIXKqueueConnection`, `POSIXEpollConnection`,
//  `PortableTLSConnection`, `SwiftSystemConnection`) that preference is a *serial* event loop. So
//  routing, middleware, handlers, filesystem calls, compression, cryptography, logging and streaming
//  producers can all end up on one reactor thread. Two consequences follow: CPU-heavy handlers on one
//  HTTP/2 connection cannot use more than one core, and one blocking handler stalls every connection
//  sharded onto that loop (CWE-410 — insufficient resource pool).
//
//  This type is the knob that decides it, per server. It is deliberately NOT an ``HTTPLimits`` field:
//  that type documents itself as engine *resource limits*, is immutable and range-validated, and
//  "which executor does application code run on" is not a limit.
//
//  The top-level wrap is unchanged. Readiness, parsing, protocol state and socket I/O keep the
//  single-owner reactor affinity every engine depends on; only the handler subtree is lifted, and
//  only at the six `respond` seams.
//

/// Where an ``HTTPServer`` runs application handlers relative to the connection's I/O reactor.
///
/// The default is ``inline``, which is byte-for-byte the behavior that shipped before this policy
/// existed. Choosing another value is a throughput/tail-latency trade, not a correctness one: every
/// policy serves an identical response on every protocol, and pipelined HTTP/1.1 responses stay in
/// request order (RFC 9112 §9.3) under all of them.
public enum HandlerExecutionPolicy: Sendable, Equatable {
    /// Run handlers on whatever executor the connection's serve task is already on.
    ///
    /// On a loop-backed backbone that is the connection's serial event loop, so read → parse → route
    /// → respond → write happens inline on one thread with no executor hop. This is the fastest path
    /// for a trivial, non-blocking handler and the reason it remains the default — but it is also the
    /// topology audit CR-F7 describes: a handler that blocks or burns CPU holds the reactor, and
    /// every other connection assigned to that shard waits behind it.
    case inline

    /// Run handlers on the global concurrent executor, returning to the reactor to write.
    ///
    /// Independent requests can then use more than one core, and a blocking handler costs a
    /// cooperative-pool thread rather than a whole reactor shard. The cost is an executor hop per
    /// request in each direction, which a trivial route pays for nothing.
    ///
    /// > Note: the hop is spelled `withTaskExecutorPreference(globalConcurrentExecutor)`, **not**
    /// > `withTaskExecutorPreference(nil)`. Passing `nil` is documented as "no preference and calling
    /// > this method will have no impact on execution semantics", so it leaves an inherited reactor
    /// > preference in place — it does not clear it. `globalConcurrentExecutor` is what Apple's own
    /// > example uses to disable an outer preference, and the preference is restored when the scoped
    /// > operation returns, which is what puts the response write back on the owning reactor.
    case concurrent

    /// Run each route ``inline`` until its own measured service time exceeds `threshold`, then
    /// ``concurrent``.
    ///
    /// The compromise between the two: a trivial route keeps the no-hop fast path, while a route that
    /// turns out to be expensive stops holding a reactor for everything else on its shard. Service
    /// time is measured against a monotonic clock per matched route and judged over a rolling window,
    /// so one slow request does not move a route permanently and a route that becomes cheap again
    /// returns to the inline path — see ``HandlerExecutionGate`` for the exact rule.
    ///
    /// A `threshold` of `.zero` moves every route off the reactor from its second request onward,
    /// since no handler runs in zero time; that is a legitimate way to spell "`.concurrent`, but pay
    /// the hop only for routes actually being used".
    case adaptive(threshold: Duration)
}
