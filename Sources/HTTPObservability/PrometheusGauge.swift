//
//  PrometheusGauge.swift
//  HTTPObservability
//
//  A Prometheus gauge: a value that can go up and down (in-flight requests, queue depths). Backed by a
//  single `Atomic<UInt64>` holding a `Double` bit pattern — set is a plain store, add/subtract a CAS
//  loop — so every mutation is lock-free and allocation-free. One class serves both swift-metrics
//  seams that map to a gauge: a non-aggregating `Recorder` ("last value wins") and a `Meter`
//  (set / increment / decrement).
//

public import Metrics
internal import Synchronization

/// A settable, incrementable value, rendered as a Prometheus `gauge` sample.
///
/// Conforms to swift-metrics' `RecorderHandler` (non-aggregating: last value wins) and
/// `MeterHandler` seams.
public final class PrometheusGauge: Sendable, RecorderHandler, MeterHandler {
    /// The sanitized metric name.
    let name: String
    /// The sanitized labels, in registration order.
    let labels: [(String, String)]

    /// The prerendered `name{labels} ` sample prefix, so a scrape appends only the value.
    private let prerenderedSample: [UInt8]
    private let bits = Atomic<UInt64>(Double.zero.bitPattern)

    init(name: String, labels: [(String, String)]) {
        self.name = name
        self.labels = labels
        prerenderedSample = PrometheusExposition.renderedSamplePrefix(name: name, labels: labels)
    }

    deinit {
        // Nothing beyond ARC — the registry drops its reference on unregistration.
    }

    /// Sets the gauge (lock-free, allocation-free).
    public func set(to value: Double) {
        bits.store(value.bitPattern, ordering: .relaxed)
    }

    /// Adds a signed amount to the gauge (lock-free, allocation-free).
    public func add(_ amount: Double) {
        var current = bits.load(ordering: .relaxed)
        while true {
            let desired = (Double(bitPattern: current) + amount).bitPattern
            let (exchanged, original) = bits.compareExchange(
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

    // MARK: - RecorderHandler (non-aggregating)

    /// Records an integer observation — a gauge keeps the last value.
    public func record(_ value: Int64) {
        set(to: Double(value))
    }

    /// Records a floating-point observation — a gauge keeps the last value.
    public func record(_ value: Double) {
        set(to: value)
    }

    // MARK: - MeterHandler

    /// Sets the gauge to an integer value.
    public func set(_ value: Int64) {
        set(to: Double(value))
    }

    /// Sets the gauge to a floating-point value.
    public func set(_ value: Double) {
        set(to: value)
    }

    /// Increments the gauge.
    public func increment(by amount: Double) {
        add(amount)
    }

    /// Decrements the gauge.
    public func decrement(by amount: Double) {
        add(-amount)
    }

    /// Appends this series' sample line to the exposition.
    func emit(into buffer: inout [UInt8]) {
        buffer.append(contentsOf: prerenderedSample)
        let value = Double(bitPattern: bits.load(ordering: .relaxed))
        PrometheusExposition.writeDouble(value, into: &buffer)
        buffer.append(UInt8(ascii: "\n"))
    }
}
