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
//  Robust cancellation depends on the responder being cooperative (the server's I/O is): on timeout the
//  losing task is cancelled and unwinds at its next suspension point, so the group returns promptly.
//

public import HTTPCore

/// Bounds each request to `duration`, returning `504` when the responder overruns the deadline.
public struct TimeoutMiddleware: HTTPMiddleware {
    private let duration: Duration
    private let clock: ContinuousClock
    private let onTimeout: @Sendable (HTTPRequest) -> ServerResponse

    /// Creates the middleware with the per-request `duration`; `onTimeout` builds the response when the
    /// deadline elapses (default: a `504 Gateway Timeout` problem+json).
    public init(
        _ duration: Duration,
        onTimeout: @escaping @Sendable (HTTPRequest) -> ServerResponse = Self.timedOut
    ) {
        self.duration = duration
        self.clock = ContinuousClock()
        self.onTimeout = onTimeout
    }

    /// Sets the deadline on the context and races the responder against it.
    public func respond(
        to request: HTTPRequest,
        body: RequestBody,
        context: RequestContext,
        next: any HTTPResponder
    ) async -> ServerResponse {
        let deadline = clock.now.advanced(by: duration)
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
