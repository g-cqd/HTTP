//
//  PrometheusDurationHistogram.swift
//  HTTPObservability
//
//  A Prometheus histogram over durations — what a swift-metrics `Timer` becomes (a histogram, not a
//  summary: quantiles then aggregate across instances server-side, which client-computed summary
//  quantiles cannot). The record path runs once per response, so it stays allocation-free: a binary
//  search for the bucket (O(log k)), then three in-place mutations under one `Mutex` — the multi-word
//  state (bucket counts + exact `Duration` sum + count) is one invariant, so a scrape under the same
//  lock always observes a consistent snapshot (buckets monotone under cumulation, `+Inf` == `_count`).
//  Bucket counts are stored per-bucket and cumulated at scrape time, where allocation is fine.
//
//  The sum is an exact fixed-point `Duration` (128-bit attoseconds), not a `Double` and not `Int64`
//  nanoseconds — no rounding drift, and no overflow trap at high throughput (an Int64 nanosecond sum
//  overflows after ~107 days at 200k rps x 5 ms).
//

public import Metrics
internal import Synchronization

/// A histogram of durations, rendered as Prometheus `_bucket` / `_sum` / `_count` samples in seconds.
///
/// Conforms to swift-metrics' `TimerHandler` seam.
public final class PrometheusDurationHistogram: Sendable, TimerHandler {
    /// The sanitized metric name.
    let name: String
    /// The sanitized labels, in registration order.
    let labels: [(String, String)]
    /// The bucket upper bounds, ascending (deduplicated by the registry).
    let bucketBounds: [Duration]

    private struct State: Sendable {
        /// Per-bucket (NON-cumulative) observation counts; cumulated at scrape time.
        var bucketCounts: [Int]
        /// The exact sum of every recorded duration.
        var sum: Duration
        /// The total number of observations (also the `+Inf` bucket).
        var count: Int
    }

    private let state: Mutex<State>
    /// Prerendered `name_bucket{labels,le="…"} ` prefixes, one per finite bucket.
    private let prerenderedBucketPrefixes: [[UInt8]]
    private let prerenderedInfinityPrefix: [UInt8]
    private let prerenderedSumPrefix: [UInt8]
    private let prerenderedCountPrefix: [UInt8]

    init(name: String, labels: [(String, String)], buckets: [Duration]) {
        self.name = name
        self.labels = labels
        bucketBounds = buckets
        state = Mutex<State>(
            State(bucketCounts: Array(repeating: 0, count: buckets.count), sum: .zero, count: 0)
        )

        let labelBytes = PrometheusExposition.renderedLabels(labels)
        prerenderedBucketPrefixes = buckets.map { bound in
            var le: [UInt8] = []
            PrometheusExposition.writeSeconds(of: bound, into: &le)
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

    /// Records one observation given in nanoseconds (the swift-metrics `Timer` seam).
    public func recordNanoseconds(_ duration: Int64) {
        record(.nanoseconds(max(duration, 0)))
    }

    /// Records one observation (negative durations clamp to zero — time does not run backwards).
    public func record(_ duration: Duration) {
        let value = max(duration, .zero)
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
        PrometheusExposition.writeSeconds(of: snapshot.sum, into: &buffer)
        buffer.append(UInt8(ascii: "\n"))
        buffer.append(contentsOf: prerenderedCountPrefix)
        buffer.append(contentsOf: String(snapshot.count).utf8)
        buffer.append(UInt8(ascii: "\n"))
    }

    /// The index of the smallest bucket whose upper bound holds `value` (`bucketBounds.count` when
    /// only `+Inf` does).
    private func firstBucketIndex(holding value: Duration) -> Int {
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
