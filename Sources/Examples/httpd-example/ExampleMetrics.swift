//
//  ExampleMetrics.swift
//  httpd-example
//
//  A minimal `HTTPMetrics` sink for the example: it counts requests and errors (the RED rate/errors
//  signals) with lock-free atomics, and renders a snapshot served at `GET /metrics`. A real deployment
//  would bridge `HTTPMetrics` to swift-metrics / swift-distributed-tracing instead; this just shows the
//  observability seam wired end-to-end (collected by `MetricsMiddleware`, surfaced by a route).
//

import HTTPCore
import HTTPServer
import Synchronization

/// Counts requests + errors for the example's `/metrics` endpoint — a demonstration ``HTTPMetrics`` sink.
final class ExampleMetrics: HTTPMetrics {
    private let requests = Atomic<Int>(0)
    private let errors = Atomic<Int>(0)

    deinit {
        // No teardown beyond ARC.
    }

    func record(method _: HTTPMethod, path _: String, status: HTTPStatus, duration _: Duration) {
        _ = requests.wrappingAdd(1, ordering: .relaxed)
        if status.code >= 400 {
            _ = errors.wrappingAdd(1, ordering: .relaxed)
        }
    }

    /// A plain-text snapshot of the counters (rate + errors), served at `/metrics`.
    func snapshot() -> String {
        """
        requests \(requests.load(ordering: .relaxed))
        errors \(errors.load(ordering: .relaxed))

        """
    }
}
