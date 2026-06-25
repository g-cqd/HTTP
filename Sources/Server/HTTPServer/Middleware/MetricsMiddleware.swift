//
//  MetricsMiddleware.swift
//  HTTPServer
//
//  Drives the ``HTTPMetrics`` observability seam: times the downstream responder chain and records one
//  metric per response (the RED signals). Implemented as ordinary middleware so it needs no hook inside
//  the server core — compose it like any other, and it costs nothing when not installed.
//
//  Generic over the clock so production uses the real ``ContinuousClock`` while tests inject a
//  deterministic one; the timing is monotonic (``ContinuousClock``), never wall-clock, so a system
//  clock step can't produce a negative or wildly inflated duration.
//

public import HTTPCore

/// Middleware that records a metric for every response via an injected ``HTTPMetrics`` sink.
public struct MetricsMiddleware<C: Clock>: HTTPMiddleware where C.Duration == Duration {
    private let metrics: any HTTPMetrics
    private let clock: C

    /// Creates the middleware recording into `metrics`, timing the chain against `clock`.
    public init(_ metrics: any HTTPMetrics, clock: C) {
        self.metrics = metrics
        self.clock = clock
    }

    /// Times the delegated response and records its method, path, status, and duration.
    public func respond(
        to request: HTTPRequest,
        body: [UInt8],
        next: any HTTPResponder
    ) async -> ServerResponse {
        let start = clock.now
        let response = await next.respond(to: request, body: body)
        metrics.record(
            method: request.method,
            path: request.path,
            status: response.head.status,
            duration: start.duration(to: clock.now)
        )
        return response
    }
}

extension MetricsMiddleware where C == ContinuousClock {
    /// Creates the middleware timing against the real ``ContinuousClock`` (the production default).
    public init(_ metrics: any HTTPMetrics) {
        self.init(metrics, clock: ContinuousClock())
    }
}
