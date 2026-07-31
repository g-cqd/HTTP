//
//  TimeoutMiddleware.swift
//  HTTPServer
//
//  A per-request deadline (RFC 9110 §15.6.5 — 504 Gateway Timeout). The middleware sets
//  ``RequestContext/deadline`` and races the downstream responder against a monotonic
//  (``ContinuousClock``) sleep: whichever finishes first wins, so a responder that produces a response
//  in time is returned untouched, while one that overruns yields `504` (an `application/problem+json`
//  body by default) and the responder task is cancelled. This is the per-*request* deadline that
//  complements the connection-level idle watchdog (`withIdleWatchdog`), which only bounds I/O stalls.
//
//  The deadline is COOPERATIVE, not preemptive, and the 2026-07-31 audit (finding 17) is explicit that
//  this is not fixable by adding more task-group logic: a `withTaskGroup` scope cannot return until
//  every child has actually exited. See the type documentation for the precise contract; the honest
//  answer for hostile handler code is a process boundary, not a Swift task.
//

public import HTTPCore

/// Bounds each request to `duration`, returning `504` when the responder overruns the deadline.
///
/// **The deadline is cooperative, not preemptive.** On expiry the middleware stops waiting for the
/// responder and cancels it, but a `withTaskGroup` scope cannot return until every child has actually
/// exited — so the `504` is delayed by however long the responder needs to reach its next suspension
/// point. A responder that blocks a thread (a synchronous `sleep`, a blocking syscall, an unbounded CPU
/// loop) therefore delays the `504` by its own full runtime and holds its connection slot for that
/// long. Handlers must check ``RequestContext/deadline`` and `Task.isCancelled` at every I/O and loop
/// boundary — ``RequestContext/timeRemaining(now:)`` exists for exactly that.
///
/// Hard isolation against uncooperative or hostile handler code requires a process boundary, not a
/// Swift task. Emitting the `504` early while leaving the responder running would only trade an
/// implicit stall for an unbounded leak of runaway tasks (CWE-400), so this type does not offer it.
public struct TimeoutMiddleware: HTTPMiddleware {
    private let duration: Duration
    private let clock: ContinuousClock
    private let onTimeout: @Sendable (HTTPRequest) -> ServerResponse

    /// Creates the middleware with the per-request `duration`.
    ///
    /// - Parameters:
    ///   - duration: how long the responder has. Narrows any deadline already on the context and never
    ///     widens it, so nesting this inside a shorter outer timeout cannot grant more time.
    ///   - onTimeout: builds the response when the deadline elapses. Defaults to a `504` problem+json.
    public init(
        _ duration: Duration,
        onTimeout: @escaping @Sendable (HTTPRequest) -> ServerResponse = Self.timedOut
    ) {
        self.duration = duration
        self.clock = ContinuousClock()
        self.onTimeout = onTimeout
    }

    /// Narrows the context's deadline and races the responder against it.
    ///
    /// Cooperative — see the type documentation. The `504` is returned once the cancelled responder
    /// unwinds, which for a cooperative one is its next suspension point.
    public func respond(
        to request: HTTPRequest,
        body: RequestBody,
        context: RequestContext,
        next: any HTTPResponder
    ) async -> ServerResponse {
        let deadline = Self.narrowed(context.deadline, to: clock.now.advanced(by: duration))
        // A `let` so the racing task closures capture it by value (a captured `var` would be shared by
        // reference — a data race the `sending`-closure check rejects).
        let context = Self.context(context, withDeadline: deadline)
        return await withTaskGroup(of: Outcome.self) { group in
            group.addTask {
                .completed(await next.respond(to: request, body: body, context: context))
            }
            group.addTask { [clock] in
                try? await clock.sleep(until: deadline, tolerance: nil)
                return .timedOut
            }
            defer { group.cancelAll() }
            for await outcome in group {
                switch outcome {
                    case .completed(let response):
                        return response
                    case .timedOut:
                        return onTimeout(request)
                }
            }
            return onTimeout(request)  // unreachable: the group always yields at least one outcome
        }
    }

    /// The narrower of an existing deadline and a proposed one.
    ///
    /// A nested timeout may only tighten the bound: widening it would let an inner middleware grant a
    /// handler more time than an outer one allowed.
    private static func narrowed(
        _ existing: ContinuousClock.Instant?,
        to proposed: ContinuousClock.Instant
    ) -> ContinuousClock.Instant {
        guard let existing else {
            return proposed
        }
        return min(existing, proposed)
    }

    /// `context` with its ``RequestContext/deadline`` set — returned as a value so the racing closures
    /// capture an immutable copy.
    private static func context(
        _ context: RequestContext,
        withDeadline deadline: ContinuousClock.Instant
    ) -> RequestContext {
        var context = context
        context.deadline = deadline
        return context
    }

    /// The first-finishing branch of the race.
    private enum Outcome: Sendable {
        case completed(ServerResponse)
        case timedOut
    }

    /// The default timeout response: a `504 Gateway Timeout` RFC 9457 problem document.
    public static func timedOut(_: HTTPRequest) -> ServerResponse {
        .problem(
            status: .gatewayTimeout,
            detail: "The server did not produce a response within the request deadline.",
            title: "Gateway Timeout"
        )
    }
}
