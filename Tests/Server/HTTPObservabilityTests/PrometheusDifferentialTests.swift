//
//  PrometheusDifferentialTests.swift
//  HTTPObservabilityTests
//
//  TEMPORARY — deleted together with the swift-prometheus dependency it compares against. Drives the
//  same register/emit sequence through the in-house backend and through swift-prometheus'
//  `PrometheusMetricsFactory`, then compares the expositions as sorted line multisets (swift-prometheus
//  emits in dictionary order; ours is deterministic — ordering is a documented deviation, neutralized
//  by the sort). The inputs avoid the other two documented deviations: label values needing escaping
//  (swift-prometheus does not escape; we do, per the spec) and non-finite gauge values (it renders
//  Swift's `inf`/`nan`; we render the canonical `+Inf`/`NaN`).
//

import Foundation
import HTTPObservability
import Metrics
import Prometheus
import Testing

@Suite("HTTPObservability — differential vs swift-prometheus")
struct PrometheusDifferentialTests {
    @Test("the same metric sequence renders the same sample lines as swift-prometheus")
    func sameSequenceSameLines() {
        let buckets: [Duration] = [.milliseconds(5), .milliseconds(10), .milliseconds(2_500)]

        let ourRegistry = PrometheusRegistry()
        var ours = HTTPObservability.PrometheusMetricsFactory(registry: ourRegistry)
        ours.durationHistogramBucketOverrides["diff_duration_seconds"] = buckets

        let theirRegistry = PrometheusCollectorRegistry()
        var theirs = Prometheus.PrometheusMetricsFactory(registry: theirRegistry)
        theirs.durationHistogramBuckets["diff_duration_seconds"] = buckets

        drive(ours)
        drive(theirs)

        var ourBuffer: [UInt8] = []
        ourRegistry.emit(into: &ourBuffer)
        var theirBuffer: [UInt8] = []
        theirRegistry.emit(into: &theirBuffer)

        let ourLines = lines(of: ourBuffer)
        let theirLines = lines(of: theirBuffer)
        #expect(ourLines == theirLines)
    }

    /// The fixed sequence: integer + fractional counters, a meter, both recorder shapes, a timer.
    private func drive(_ factory: any MetricsFactory) {
        let getCounter = factory.makeCounter(
            label: "diff_requests_total",
            dimensions: [("method", "GET"), ("status", "200")]
        )
        getCounter.increment(by: 3)
        factory.makeCounter(
            label: "diff_requests_total",
            dimensions: [("method", "POST"), ("status", "201")]
        )
        .increment(by: 1)

        let bytes = factory.makeFloatingPointCounter(label: "diff_bytes_total", dimensions: [])
        bytes.increment(by: 1.5)
        bytes.increment(by: 2.25)

        let meter = factory.makeMeter(label: "diff_inflight", dimensions: [])
        meter.set(Int64(5))
        meter.increment(by: 2.5)
        meter.decrement(by: 1)

        factory.makeRecorder(label: "diff_last", dimensions: [], aggregate: false).record(42.0)

        let sizes = factory.makeRecorder(label: "diff_sizes", dimensions: [], aggregate: true)
        sizes.record(Int64(3))
        sizes.record(7.0)
        sizes.record(5_000.0)

        let timer = factory.makeTimer(
            label: "diff_duration_seconds",
            dimensions: [("method", "GET")]
        )
        timer.recordNanoseconds(3_000_000)
        timer.recordNanoseconds(7_000_000)
        timer.recordNanoseconds(1_000_000_000)
    }

    private func lines(of buffer: [UInt8]) -> [String] {
        (String(bytes: buffer, encoding: .utf8) ?? "")
            .split(separator: "\n")
            .map(String.init)
            .sorted()
    }
}
