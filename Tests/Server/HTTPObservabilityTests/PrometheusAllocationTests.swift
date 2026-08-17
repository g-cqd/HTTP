//
//  PrometheusAllocationTests.swift
//  HTTPObservabilityTests
//
//  The zero-allocation guard on the metric hot paths, via the `mallocDelta` oracle (the
//  CHTTPTestMalloc per-thread heap counter behind `expectAllocations`). Recording a metric runs once
//  per response, so the increment paths — counter atomic add, gauge CAS, histogram record under its
//  mutex — must not allocate at all, and the bound is EXACT (zero) even in the unoptimized test
//  build. The measured loops are `while` loops on purpose: `for _ in a ..< b` itself allocates once
//  per iteration in the -Onone test build (see MultipartAllocationTests' boundary-length note), which
//  would charge the oracle for the harness rather than the path under test. Registration and scraping
//  may allocate; they are not on the request path.
//

import HTTPObservability
import HTTPTestSupport
import Testing

@Suite("HTTPObservability — Prometheus allocation oracle")
struct PrometheusAllocationTests {
    @Test("counter, gauge, and histogram record paths make zero heap allocations")
    func incrementPathsDoNotAllocate() {
        let registry = PrometheusRegistry()
        let counter = registry.makeCounter(name: "alloc_total")
        let gauge = registry.makeGauge(name: "alloc_gauge")
        let histogram = registry.makeDurationHistogram(
            name: "alloc_seconds",
            buckets: [.milliseconds(5), .milliseconds(50), .seconds(1)]
        )

        // Warm up once so lazy one-time initialization never skews the measurement.
        counter.increment(by: Int64(1))
        counter.increment(by: 0.5)
        gauge.set(to: 1)
        gauge.add(2)
        histogram.record(.milliseconds(3))
        histogram.recordNanoseconds(7_000_000)

        let measured = expectAllocations(noMoreThan: 0) {
            var tick = 0
            while tick < 1_000 {
                counter.increment(by: Int64(1))
                counter.increment(by: 0.25)
                gauge.add(1)
                gauge.set(to: Double(tick))
                histogram.recordNanoseconds(Int64(tick) * 100_000)
                tick += 1
            }
        }
        // `nil` only where counting is unavailable (non-Darwin); the oracle then asserted nothing.
        if let measured {
            #expect(measured == 0)
        }
    }
}
