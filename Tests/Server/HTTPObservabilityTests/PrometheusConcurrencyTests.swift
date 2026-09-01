//
//  PrometheusConcurrencyTests.swift
//  HTTPObservabilityTests
//
//  The registry is written on request paths and scraped concurrently. Two contracts: parallel
//  increments are never lost (the counter is a lock-free atomic, the histogram a single mutex), and a
//  scrape DURING a storm returns a consistent snapshot — parsed back, every line is well-formed and
//  every histogram invariant holds (cumulative buckets monotone, `+Inf` bucket == `_count`), with no
//  torn lines.
//

import Foundation
import HTTPObservability
import Testing

@Suite("HTTPObservability — Prometheus concurrency")
struct PrometheusConcurrencyTests {
    @Test("N parallel tasks incrementing one counter land the exact final count")
    func parallelIncrementsAreExact() async {
        let registry = PrometheusRegistry()
        let counter = registry.makeCounter(name: "storm_total")
        let tasks = 8
        let perTask = 10_000
        await withTaskGroup(of: Void.self) { group in
            for _ in 0 ..< tasks {
                group.addTask {
                    for _ in 0 ..< perTask {
                        counter.increment(by: Int64(1))
                    }
                }
            }
        }
        #expect(render(registry) == "# TYPE storm_total counter\nstorm_total \(tasks * perTask)\n")
    }

    @Test("a scrape during a storm parses back consistent — no torn lines, invariants hold")
    func scrapeDuringStormIsConsistent() async {
        let registry = PrometheusRegistry()
        let counter = registry.makeCounter(name: "storm_requests_total")
        let histogram = registry.makeDurationHistogram(
            name: "storm_seconds",
            buckets: [.milliseconds(1), .milliseconds(10), .milliseconds(100)]
        )
        let writers = 4
        let perWriter = 5_000

        await withTaskGroup(of: Void.self) { group in
            for _ in 0 ..< writers {
                group.addTask {
                    for tick in 0 ..< perWriter {
                        counter.increment(by: Int64(1))
                        histogram.record(.milliseconds(tick % 20))
                    }
                }
            }
            group.addTask {
                for _ in 0 ..< 100 {
                    assertConsistent(exposition: render(registry))
                    await Task.yield()
                }
            }
        }

        // After the storm settles, the totals are exact.
        let settled = render(registry)
        #expect(settled.contains("storm_requests_total \(writers * perWriter)"))
        #expect(settled.contains("storm_seconds_count \(writers * perWriter)"))
        assertConsistent(exposition: settled)
    }

    /// Parses an exposition back: every line is `# …` or `name[{labels}] value`, and the histogram's
    /// cumulative buckets are monotone with `le="+Inf"` equal to `_count`.
    private func assertConsistent(exposition: String) {
        var bucketCounts: [Int] = []
        var infinityCount: Int?
        var histogramCount: Int?
        for line in exposition.split(separator: "\n") {
            if line.hasPrefix("# ") {
                continue
            }
            guard let separator = line.lastIndex(of: " "),
                let value = Double(line[line.index(after: separator)...])
            else {
                Issue.record("torn or malformed sample line: '\(line)'")
                return
            }
            let series = line[..<separator]
            if series.hasPrefix("storm_seconds_bucket") {
                if series.contains("le=\"+Inf\"") {
                    infinityCount = Int(value)
                }
                else {
                    bucketCounts.append(Int(value))
                }
            }
            else if series == "storm_seconds_count" {
                histogramCount = Int(value)
            }
        }
        #expect(bucketCounts == bucketCounts.sorted(), "cumulative buckets must be monotone")
        if let last = bucketCounts.last, let infinityCount {
            #expect(infinityCount >= last, "+Inf must dominate every finite bucket")
        }
        #expect(infinityCount == histogramCount, "the +Inf bucket must equal _count")
    }

    private func render(_ registry: PrometheusRegistry) -> String {
        var buffer: [UInt8] = []
        registry.emit(into: &buffer)
        return String(bytes: buffer, encoding: .utf8) ?? ""
    }
}
