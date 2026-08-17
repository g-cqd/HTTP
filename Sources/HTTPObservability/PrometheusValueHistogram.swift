//
//  PrometheusValueHistogram.swift
//  HTTPObservability
//
//  A Prometheus histogram over plain values — what an AGGREGATING swift-metrics `Recorder` (a
//  `Summary` in swift-metrics 2.x terms) becomes. Same shape as ``PrometheusDurationHistogram`` with
//  `Double` in place of `Duration`: binary-searched bucket, three in-place mutations under one
//  `Mutex`, per-bucket counts cumulated at scrape time. The two are separate types (not one generic)
//  so the timer keeps an exact fixed-point sum while values keep native `Double` arithmetic.
//

public import Metrics
internal import Synchronization

/// A histogram of values, rendered as Prometheus `_bucket` / `_sum` / `_count` samples.
///
/// Conforms to swift-metrics' `RecorderHandler` seam (the aggregating shape).
public final class PrometheusValueHistogram: Sendable, RecorderHandler {
    /// The sanitized metric name.
    let name: String
    /// The sanitized labels, in registration order.
    let labels: [(String, String)]
    /// The bucket upper bounds, ascending (deduplicated, finite; enforced by the registry).
    let bucketBounds: [Double]

    private struct State: Sendable {
        /// Per-bucket (NON-cumulative) observation counts; cumulated at scrape time.
        var bucketCounts: [Int]
        /// The sum of every recorded value.
        var sum: Double
        /// The total number of observations (also the `+Inf` bucket).
        var count: Int
    }

    private let state: Mutex<State>
    /// Prerendered `name_bucket{labels,le="…"} ` prefixes, one per finite bucket.
    private let prerenderedBucketPrefixes: [[UInt8]]
    private let prerenderedInfinityPrefix: [UInt8]
    private let prerenderedSumPrefix: [UInt8]
    private let prerenderedCountPrefix: [UInt8]

    init(name: String, labels: [(String, String)], buckets: [Double]) {
        self.name = name
        self.labels = labels
        bucketBounds = buckets
        state = Mutex<State>(
            State(bucketCounts: Array(repeating: 0, count: buckets.count), sum: 0, count: 0)
        )

        let labelBytes = PrometheusExposition.renderedLabels(labels)
        prerenderedBucketPrefixes = buckets.map { bound in
            var le: [UInt8] = []
            PrometheusExposition.writeDouble(bound, into: &le)
            return Self.bucketPrefix(name: name, labelBytes: labelBytes, le: le)
        }
        prerenderedInfinityPrefix = Self.bucketPrefix(
            name: name,
            labelBytes: labelBytes,
            le: Array("+Inf".utf8)
        )
        prerenderedSumPrefix = PrometheusExposition.renderedSamplePrefix(
            name: name + "_sum",
            labels: labels
        )
        prerenderedCountPrefix = PrometheusExposition.renderedSamplePrefix(
            name: name + "_count",
            labels: labels
        )
    }

    deinit {
        // Nothing beyond ARC — the registry drops its reference on unregistration.
    }

    /// Records an integer observation (the swift-metrics `Recorder` seam).
    public func record(_ value: Int64) {
        record(Double(value))
    }

    /// Records one observation.
    public func record(_ value: Double) {
        let index = firstBucketIndex(holding: value)
        state.withLock { state in
            if index < state.bucketCounts.count {
                state.bucketCounts[index] += 1
            }
            state.sum += value
            state.count += 1
        }
    }

    /// Appends this series' `_bucket` / `_sum` / `_count` lines to the exposition.
    func emit(into buffer: inout [UInt8]) {
        let snapshot = state.withLock { locked in
            State(bucketCounts: locked.bucketCounts, sum: locked.sum, count: locked.count)
        }
        var cumulative = 0
        for (index, prefix) in prerenderedBucketPrefixes.enumerated() {
            cumulative += snapshot.bucketCounts[index]
            buffer.append(contentsOf: prefix)
            buffer.append(contentsOf: String(cumulative).utf8)
            buffer.append(UInt8(ascii: "\n"))
        }
        buffer.append(contentsOf: prerenderedInfinityPrefix)
        buffer.append(contentsOf: String(snapshot.count).utf8)
        buffer.append(UInt8(ascii: "\n"))
        buffer.append(contentsOf: prerenderedSumPrefix)
        PrometheusExposition.writeDouble(snapshot.sum, into: &buffer)
        buffer.append(UInt8(ascii: "\n"))
        buffer.append(contentsOf: prerenderedCountPrefix)
        buffer.append(contentsOf: String(snapshot.count).utf8)
        buffer.append(UInt8(ascii: "\n"))
    }

    /// The index of the smallest bucket whose upper bound holds `value` (`bucketBounds.count` when
    /// only `+Inf` does — including for NaN, which belongs to no finite bucket).
    private func firstBucketIndex(holding value: Double) -> Int {
        guard !value.isNaN else {
            return bucketBounds.count
        }
        var low = 0
        var high = bucketBounds.count
        while low < high {
            let mid = (low + high) / 2
            if bucketBounds[mid] < value {
                low = mid + 1
            }
            else {
                high = mid
            }
        }
        return low
    }

    private static func bucketPrefix(name: String, labelBytes: [UInt8], le: [UInt8]) -> [UInt8] {
        var prefix: [UInt8] = []
        prefix.append(contentsOf: name.utf8)
        prefix.append(contentsOf: "_bucket{".utf8)
        if !labelBytes.isEmpty {
            prefix.append(contentsOf: labelBytes)
            prefix.append(UInt8(ascii: ","))
        }
        prefix.append(contentsOf: "le=\"".utf8)
        prefix.append(contentsOf: le)
        prefix.append(contentsOf: "\"} ".utf8)
        return prefix
    }
}
