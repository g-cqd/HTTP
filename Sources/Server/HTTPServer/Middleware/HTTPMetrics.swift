//
//  HTTPMetrics.swift
//  HTTPServer
//
//  The observability seam: a per-response metrics sink the server has no other way to surface (the
//  audit flagged the absence of a metrics/tracing hook). Kept a dependency-free protocol so a consumer
//  bridges it to swift-metrics / swift-distributed-tracing / a custom backend without this package
//  taking on those dependencies. Driven by ``MetricsMiddleware``.
//

public import HTTPCore

/// A sink for per-response metrics — the RED signals (rate, errors, duration).
public protocol HTTPMetrics: Sendable {
    /// Records one completed response: the request's method and path, the response status, and how long
    /// the responder chain took to produce it.
    func record(method: HTTPMethod, path: String, status: HTTPStatus, duration: Duration)
}
