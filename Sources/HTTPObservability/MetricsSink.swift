//
//  MetricsSink.swift
//  HTTPObservability
//
//  Bridges the dependency-free `HTTPMetrics` seam to swift-metrics: one counter + one latency timer per
//  response, dimensioned by HTTP method and response status ONLY. The request path is deliberately never
//  a dimension — it would explode series cardinality (`/items/1`, `/items/2`, …) and, being
//  attacker-controlled, would expose the swift-prometheus label-injection issue (CVE-2024-28867);
//  method × status stays bounded and trusted. Bootstrap a backend (e.g. ``PrometheusExporter/bootstrap()``)
//  once at startup; with none bootstrapped, every record is a no-op. Drive it with `MetricsMiddleware`.
//

public import HTTPCore
public import HTTPServer
internal import Metrics

/// An `HTTPMetrics` sink recording the swift-metrics RED signals, dimensioned by method × status.
public struct MetricsSink: HTTPMetrics {
    /// The counter metric label (default `http_requests_total`).
    public let requestsLabel: String
    /// The latency timer metric label (default `http_request_duration_seconds`).
    public let durationLabel: String

    /// Creates the sink with the metric labels it emits under.
    public init(
        requestsLabel: String = "http_requests_total",
        durationLabel: String = "http_request_duration_seconds"
    ) {
        self.requestsLabel = requestsLabel
        self.durationLabel = durationLabel
    }

    /// Records one response as a counter increment and a latency sample, tagged by method and status.
    ///
    /// `path` is intentionally not a metric dimension — see the cardinality / label-injection note above.
    public func record(
        method: HTTPMethod,
        path _: String,
        status: HTTPStatus,
        duration: Duration
    ) {
        let dimensions = [("method", method.rawValue), ("status", String(status.code))]
        Counter(label: requestsLabel, dimensions: dimensions).increment()
        Timer(label: durationLabel, dimensions: dimensions)
            .recordNanoseconds(Self.nanoseconds(duration))
    }

    /// The whole-nanosecond magnitude of `duration` (a request latency never approaches the Int64 bound).
    private static func nanoseconds(_ duration: Duration) -> Int64 {
        let components = duration.components
        return components.seconds * 1_000_000_000 + components.attoseconds / 1_000_000_000
    }
}
