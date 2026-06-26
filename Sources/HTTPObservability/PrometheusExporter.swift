//
//  PrometheusExporter.swift
//  HTTPObservability
//
//  The Prometheus scrape endpoint: a `PrometheusCollectorRegistry` (the swift-metrics backend the
//  ``MetricsSink`` records into once bootstrapped) rendered in the text exposition format (version 0.0.4)
//  for `/metrics`. swift-metrics is bootstrapped process-globally (once), so call ``bootstrap()`` at
//  startup; the registry is injectable so a test can record into one it also renders.
//

internal import HTTPCore
public import HTTPServer
internal import Metrics
public import Prometheus

/// Renders a Prometheus text-exposition `/metrics` endpoint over a swift-metrics registry.
public struct PrometheusExporter: Sendable {
    /// The Prometheus exposition content type, pinning the format version (0.0.4).
    public static let contentType = "text/plain; version=0.0.4; charset=utf-8"

    private let registry: PrometheusCollectorRegistry

    /// Creates an exporter over `registry` (a fresh one by default).
    public init(registry: PrometheusCollectorRegistry = PrometheusCollectorRegistry()) {
        self.registry = registry
    }

    /// Bootstraps swift-metrics to record into this exporter's registry; call once, at startup.
    public func bootstrap() {
        MetricsSystem.bootstrap(PrometheusMetricsFactory(registry: registry))
    }

    /// The current metrics in the Prometheus text exposition format.
    public func render() -> [UInt8] {
        var buffer: [UInt8] = []
        registry.emit(into: &buffer)
        return buffer
    }

    /// A ready-to-serve `/metrics` response: status 200 with the Prometheus content type.
    public func metricsResponse() -> ServerResponse {
        var fields = HTTPFields()
        _ = fields.setValue(Self.contentType, for: .contentType)
        return ServerResponse(HTTPResponse(status: .ok, headerFields: fields), body: render())
    }

    /// A `GET` route serving the exposition at `path` (default `/metrics`).
    public func metricsRoute(path: String = "/metrics") -> Route {
        let exporter = self
        return Route.get(path) { _, _, _ in exporter.metricsResponse() }
    }
}
