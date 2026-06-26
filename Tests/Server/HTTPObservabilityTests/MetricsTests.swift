//
//  MetricsTests.swift
//  HTTPObservabilityTests
//
//  The swift-metrics → Prometheus bridge: `MetricsSink` records a method×status counter + latency timer
//  into a `PrometheusCollectorRegistry`, and `PrometheusExporter` renders the text exposition. The key
//  invariant beyond "it records" is that the request path is NEVER a label — bounding cardinality and
//  sidestepping the swift-prometheus label-injection issue (CVE-2024-28867).
//

import Foundation
import HTTPCore
import HTTPObservability
import HTTPServer
import Metrics
import Prometheus
import Testing

@Suite("HTTPObservability — Prometheus metrics")
struct MetricsTests {
    /// One process-wide swift-metrics bootstrap into a shared registry (a `static let` runs exactly once,
    /// avoiding the bootstrap-twice precondition).
    static let registry: PrometheusCollectorRegistry = {
        let registry = PrometheusCollectorRegistry()
        MetricsSystem.bootstrap(PrometheusMetricsFactory(registry: registry))
        return registry
    }()

    @Test("records a method×status counter + timer, never the path (cardinality / CVE-2024-28867)")
    func recordsMethodStatusNotPath() {
        let registry = Self.registry
        MetricsSink(requestsLabel: "g1_requests_total", durationLabel: "g1_duration_seconds")
            .record(method: .get, path: "/items/42", status: .ok, duration: .milliseconds(5))

        let exposition = text(emit(registry))
        #expect(exposition.contains("g1_requests_total"))
        #expect(exposition.contains("method=\"GET\""))
        #expect(exposition.contains("status=\"200\""))
        #expect(exposition.contains("g1_duration_seconds"))
        #expect(!exposition.contains("/items/42"))  // the path is never emitted as a label
    }

    @Test("the exporter serves the exposition with the Prometheus content type")
    func exporterServesExposition() {
        let registry = Self.registry
        MetricsSink(requestsLabel: "g1_export_total", durationLabel: "g1_export_seconds")
            .record(method: .post, path: "/x", status: .created, duration: .milliseconds(1))

        let response = PrometheusExporter(registry: registry).metricsResponse()
        #expect(response.head.status.code == 200)
        #expect(response.head.headerFields[.contentType] == PrometheusExporter.contentType)
        #expect(!response.body.isEmpty)
        #expect(text(response.body).contains("g1_export_total"))
    }

    private func emit(_ registry: PrometheusCollectorRegistry) -> [UInt8] {
        var buffer: [UInt8] = []
        registry.emit(into: &buffer)
        return buffer
    }

    /// The bytes decoded as UTF-8 (the failable initializer the lint rules prefer), empty on failure.
    private func text(_ bytes: [UInt8]) -> String {
        String(bytes: bytes, encoding: .utf8) ?? ""
    }
}
