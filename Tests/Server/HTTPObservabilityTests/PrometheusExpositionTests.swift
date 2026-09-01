//
//  PrometheusExpositionTests.swift
//  HTTPObservabilityTests
//
//  Golden-file tests for the in-house Prometheus text exposition (format 0.0.4): a fixed
//  register/emit sequence must produce EXACTLY these bytes. The goldens are the contract the
//  `/metrics` endpoint ships — counter/gauge/histogram families, `# HELP`/`# TYPE` lines, label
//  escaping (backslash, quote, newline), name sanitization, canonical `NaN`/`+Inf`/`-Inf`, and the
//  deterministic family/series ordering the in-house registry guarantees (which dictionary-ordered
//  swift-prometheus never did).
//

import Foundation
import HTTPObservability
import Metrics
import Testing

@Suite("HTTPObservability — Prometheus exposition goldens")
struct PrometheusExpositionTests {
    @Test("an unlabeled counter with help renders HELP, TYPE, and an integer sample")
    func unlabeledCounterGolden() {
        let registry = PrometheusRegistry()
        registry.makeCounter(name: "requests_total", help: "Total requests served.")
            .increment(by: Int64(3))

        let expected = """
            # HELP requests_total Total requests served.
            # TYPE requests_total counter
            requests_total 3

            """
        #expect(render(registry) == expected)
    }

    @Test("labeled counter series render sorted by label key, one TYPE line per family")
    func labeledCounterGolden() {
        let registry = PrometheusRegistry()
        let labelsGet = [("method", "GET"), ("status", "200")]
        let labelsPost = [("method", "POST"), ("status", "201")]
        registry.makeCounter(name: "http_requests_total", labels: labelsPost)
            .increment(by: Int64(1))
        registry.makeCounter(name: "http_requests_total", labels: labelsGet).increment(by: Int64(2))

        let expected = """
            # TYPE http_requests_total counter
            http_requests_total{method="GET",status="200"} 2
            http_requests_total{method="POST",status="201"} 1

            """
        #expect(render(registry) == expected)
    }

    @Test("a fractional counter increment switches the sample to a floating-point rendering")
    func fractionalCounterGolden() {
        let registry = PrometheusRegistry()
        let counter = registry.makeCounter(name: "bytes_total")
        counter.increment(by: Int64(2))
        counter.increment(by: 1.5)

        #expect(render(registry) == "# TYPE bytes_total counter\nbytes_total 3.5\n")
    }

    @Test("gauges render Double values, with canonical NaN / +Inf / -Inf")
    func gaugeGolden() {
        let registry = PrometheusRegistry()
        registry.makeGauge(name: "temperature", labels: [("kind", "nan")]).set(to: .nan)
        registry.makeGauge(name: "temperature", labels: [("kind", "ninf")]).set(to: -.infinity)
        registry.makeGauge(name: "temperature", labels: [("kind", "pinf")]).set(to: .infinity)
        registry.makeGauge(name: "temperature", labels: [("kind", "plain")]).set(to: 2.5)
        _ = registry.makeGauge(name: "temperature", labels: [("kind", "zero")])

        let expected = """
            # TYPE temperature gauge
            temperature{kind="nan"} NaN
            temperature{kind="ninf"} -Inf
            temperature{kind="pinf"} +Inf
            temperature{kind="plain"} 2.5
            temperature{kind="zero"} 0.0

            """
        #expect(render(registry) == expected)
    }

    @Test("label values escape backslash, quote, and newline per the spec; empty values render")
    func escapingGolden() {
        let registry = PrometheusRegistry()
        registry
            .makeCounter(name: "escape_total", labels: [("path", "he said \"hi\"\n\\end")])
            .increment(by: Int64(1))
        registry.makeCounter(name: "escape_total", labels: [("path", "")]).increment(by: Int64(2))

        let expected = """
            # TYPE escape_total counter
            escape_total{path=""} 2
            escape_total{path="he said \\"hi\\"\\n\\\\end"} 1

            """
        #expect(render(registry) == expected)
    }

    @Test("metric and label names sanitize to the spec's character sets; help escapes newlines")
    func sanitizationGolden() {
        let registry = PrometheusRegistry()
        registry
            .makeCounter(
                name: "1my.metric-total",
                labels: [("label-name.bad", "kept-as.is")],
                help: "line one\nline \\ two"
            )
            .increment(by: Int64(1))

        let expected = """
            # HELP _my_metric_total line one\\nline \\\\ two
            # TYPE _my_metric_total counter
            _my_metric_total{label_name_bad="kept-as.is"} 1

            """
        #expect(render(registry) == expected)
    }

    @Test("a labeled timer histogram renders cumulative buckets, +Inf == count, and an exact sum")
    func timerHistogramGolden() {
        let registry = PrometheusRegistry()
        let histogram = registry.makeDurationHistogram(
            name: "t_seconds",
            labels: [("method", "GET")],
            buckets: [.milliseconds(5), .milliseconds(10)]
        )
        histogram.record(.milliseconds(3))
        histogram.record(.milliseconds(7))
        histogram.record(.milliseconds(20))

        let expected = """
            # TYPE t_seconds histogram
            t_seconds_bucket{method="GET",le="0.005"} 1
            t_seconds_bucket{method="GET",le="0.01"} 2
            t_seconds_bucket{method="GET",le="+Inf"} 3
            t_seconds_sum{method="GET"} 0.03
            t_seconds_count{method="GET"} 3

            """
        #expect(render(registry) == expected)
    }

    @Test("the default timer buckets render as the documented le series (1 ms … 10 s)")
    func defaultTimerBucketsGolden() {
        let registry = PrometheusRegistry()
        var factory = PrometheusMetricsFactory(registry: registry)
        _ = factory.makeTimer(label: "d_seconds", dimensions: [])

        let expected = """
            # TYPE d_seconds histogram
            d_seconds_bucket{le="0.001"} 0
            d_seconds_bucket{le="0.0025"} 0
            d_seconds_bucket{le="0.005"} 0
            d_seconds_bucket{le="0.01"} 0
            d_seconds_bucket{le="0.025"} 0
            d_seconds_bucket{le="0.05"} 0
            d_seconds_bucket{le="0.1"} 0
            d_seconds_bucket{le="0.25"} 0
            d_seconds_bucket{le="0.5"} 0
            d_seconds_bucket{le="1.0"} 0
            d_seconds_bucket{le="2.5"} 0
            d_seconds_bucket{le="5.0"} 0
            d_seconds_bucket{le="10.0"} 0
            d_seconds_bucket{le="+Inf"} 0
            d_seconds_sum 0.0
            d_seconds_count 0

            """
        #expect(render(registry) == expected)

        // Bucket overrides are per timer label, via the factory the exporter configures.
        factory.durationHistogramBucketOverrides["o_seconds"] = [.seconds(1)]
        let timer = factory.makeTimer(label: "o_seconds", dimensions: [])
        timer.recordNanoseconds(2_000_000_000)
        #expect(render(registry).contains("o_seconds_bucket{le=\"1.0\"} 0"))
        #expect(render(registry).contains("o_seconds_bucket{le=\"+Inf\"} 1"))
    }

    @Test("an aggregating recorder becomes a value histogram with Double le bounds")
    func valueHistogramGolden() {
        let registry = PrometheusRegistry()
        var factory = PrometheusMetricsFactory(registry: registry)
        factory.valueHistogramBucketOverrides["sizes"] = [5, 10]
        let recorder = factory.makeRecorder(label: "sizes", dimensions: [], aggregate: true)
        recorder.record(Int64(3))
        recorder.record(7.0)

        let expected = """
            # TYPE sizes histogram
            sizes_bucket{le="5.0"} 1
            sizes_bucket{le="10.0"} 2
            sizes_bucket{le="+Inf"} 2
            sizes_sum 10.0
            sizes_count 2

            """
        #expect(render(registry) == expected)
    }

    @Test("families emit sorted by metric name, whatever the registration order")
    func familyOrderingGolden() {
        let registry = PrometheusRegistry()
        registry.makeCounter(name: "z_total").increment(by: Int64(1))
        registry.makeGauge(name: "a_gauge").set(to: 1)
        let expected = """
            # TYPE a_gauge gauge
            a_gauge 1.0
            # TYPE z_total counter
            z_total 1

            """
        #expect(render(registry) == expected)
    }

    @Test("a destroyed handler leaves the exposition (the swift-metrics destroy seam)")
    func destroyRemovesSeries() {
        let registry = PrometheusRegistry()
        let factory = PrometheusMetricsFactory(registry: registry)
        let counter = factory.makeCounter(label: "gone_total", dimensions: [])
        counter.increment(by: Int64(1))
        #expect(render(registry).contains("gone_total 1"))

        factory.destroyCounter(counter)
        #expect(render(registry).isEmpty)
    }

    private func render(_ registry: PrometheusRegistry) -> String {
        var buffer: [UInt8] = []
        registry.emit(into: &buffer)
        return String(bytes: buffer, encoding: .utf8) ?? ""
    }
}
