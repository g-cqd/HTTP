//
//  PrometheusCounter.swift
//  HTTPObservability
//
//  A Prometheus counter: a cumulative, monotonically non-decreasing value. The increment path is the
//  per-request hot path (`MetricsSink` bumps one per response), so it is LOCK-FREE and allocation-free:
//  an `Atomic<Int64>` for the integer fast path plus an `Atomic<UInt64>` carrying the bit pattern of a
//  floating-point remainder (CAS loop), mirroring the split swift-prometheus used so the rendered value
//  stays an integer (`3`, not `3.0`) until a fractional increment actually happens.
//

public import Metrics
internal import Synchronization

/// A monotonically increasing counter, rendered as a Prometheus `counter` sample.
///
/// Conforms to swift-metrics' `CounterHandler` and `FloatingPointCounterHandler` seams.
public final class PrometheusCounter: Sendable, CounterHandler, FloatingPointCounterHandler {
    /// The sanitized metric name.
    let name: String
    /// The sanitized labels, in registration order.
    let labels: [(String, String)]

    /// The prerendered `name{labels} ` sample prefix, so a scrape appends only the value.
    private let prerenderedSample: [UInt8]
    private let wholePart = Atomic<Int64>(0)
    private let fractionalPart = Atomic<UInt64>(Double.zero.bitPattern)

    init(name: String, labels: [(String, String)]) {
        self.name = name
        self.labels = labels
        prerenderedSample = PrometheusExposition.renderedSamplePrefix(name: name, labels: labels)
    }

    deinit {
        // Nothing beyond ARC — the registry drops its reference on unregistration.
    }

    /// Adds one to the counter (lock-free, allocation-free).
    public func increment() {
        increment(by: Int64(1))
    }

    /// Adds a non-negative amount to the counter (lock-free, allocation-free).
    public func increment(by amount: Int64) {
        precondition(amount >= 0, "a counter is monotonic — increments must be non-negative")
        wholePart.wrappingAdd(amount, ordering: .relaxed)
    }

    /// Adds a non-negative floating-point amount to the counter (lock-free, allocation-free).
    public func increment(by amount: Double) {
        precondition(amount >= 0, "a counter is monotonic — increments must be non-negative")
        var current = fractionalPart.load(ordering: .relaxed)
        while true {
            let desired = (Double(bitPattern: current) + amount).bitPattern
            let (exchanged, original) = fractionalPart.compareExchange(
                expected: current,
                desired: desired,
                ordering: .relaxed
            )
            if exchanged {
                return
            }
            current = original
        }
    }

    /// Resets the counter to zero (swift-metrics' restart semantics).
    public func reset() {
        wholePart.store(0, ordering: .relaxed)
        fractionalPart.store(Double.zero.bitPattern, ordering: .relaxed)
    }

    /// Appends this series' sample line to the exposition.
    func emit(into buffer: inout [UInt8]) {
        buffer.append(contentsOf: prerenderedSample)
        let fractional = Double(bitPattern: fractionalPart.load(ordering: .relaxed))
        let whole = wholePart.load(ordering: .relaxed)
        if fractional == .zero {
            buffer.append(contentsOf: String(whole).utf8)
        }
        else {
            PrometheusExposition.writeDouble(fractional + Double(whole), into: &buffer)
        }
        buffer.append(UInt8(ascii: "\n"))
    }
}
