//
//  PrometheusMetricsFactory.swift
//  HTTPObservability
//
//  The swift-metrics `MetricsFactory` over ``PrometheusRegistry`` — the drop-in for the factory
//  swift-prometheus shipped. The mapping follows Prometheus convention: `Counter` → counter,
//  `FloatingPointCounter` → counter, `Meter` and non-aggregating `Recorder` → gauge, aggregating
//  `Recorder` → value histogram, `Timer` → duration histogram. Every destroy hook unregisters the
//  handler so a destroyed metric leaves the exposition.
//
//  The default timer buckets deliberately EXTEND swift-prometheus' defaults (the Prometheus Go
//  client's `DefBuckets`: 5 ms … 10 s) with 1 ms and 2.5 ms: an in-process router answers most
//  requests under 5 ms, and without sub-5 ms buckets every healthy request lands in the first bucket,
//  flattening p50/p90 into "somewhere below 5 ms". Override per exporter/factory when scraping a
//  slower service.
//

public import Metrics

/// A `MetricsFactory` backing swift-metrics with a ``PrometheusRegistry``.
public struct PrometheusMetricsFactory: MetricsFactory {
    /// The default request-duration buckets: Prometheus `DefBuckets` extended down to 1 ms.
    public static let defaultDurationHistogramBuckets: [Duration] = [
        .milliseconds(1), .microseconds(2_500), .milliseconds(5), .milliseconds(10),
        .milliseconds(25), .milliseconds(50), .milliseconds(100), .milliseconds(250),
        .milliseconds(500), .seconds(1), .milliseconds(2_500), .seconds(5), .seconds(10)
    ]

    /// The default value buckets for aggregating recorders (swift-prometheus' defaults, kept).
    public static let defaultValueHistogramBuckets: [Double] = [
        5, 10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000
    ]

    /// The registry every handler this factory makes registers into.
    public var registry: PrometheusRegistry

    /// The buckets for timers without a per-label override.
    public var durationHistogramBuckets: [Duration]

    /// Per-timer-label bucket overrides.
    public var durationHistogramBucketOverrides: [String: [Duration]]

    /// The buckets for aggregating recorders without a per-label override.
    public var valueHistogramBuckets: [Double]

    /// Per-recorder-label bucket overrides.
    public var valueHistogramBucketOverrides: [String: [Double]]

    /// Creates a factory over `registry` with the default bucket configuration.
    public init(registry: PrometheusRegistry) {
        self.registry = registry
        durationHistogramBuckets = Self.defaultDurationHistogramBuckets
        durationHistogramBucketOverrides = [:]
        valueHistogramBuckets = Self.defaultValueHistogramBuckets
        valueHistogramBucketOverrides = [:]
    }

    // MARK: - MetricsFactory

    /// Makes (or dedupes to) the counter for `label` + `dimensions`.
    public func makeCounter(label: String, dimensions: [(String, String)]) -> any CounterHandler {
        registry.makeCounter(name: label, labels: dimensions)
    }

    /// Makes (or dedupes to) the floating-point counter for `label` + `dimensions`.
    public func makeFloatingPointCounter(
        label: String,
        dimensions: [(String, String)]
    ) -> any FloatingPointCounterHandler {
        registry.makeCounter(name: label, labels: dimensions)
    }

    /// Makes a gauge (non-aggregating) or a value histogram (aggregating) for `label`.
    public func makeRecorder(
        label: String,
        dimensions: [(String, String)],
        aggregate: Bool
    ) -> any RecorderHandler {
        guard aggregate else {
            return registry.makeGauge(name: label, labels: dimensions)
        }
        let buckets = valueHistogramBucketOverrides[label] ?? valueHistogramBuckets
        return registry.makeValueHistogram(name: label, labels: dimensions, buckets: buckets)
    }

    /// Makes (or dedupes to) the gauge for `label` + `dimensions`.
    public func makeMeter(label: String, dimensions: [(String, String)]) -> any MeterHandler {
        registry.makeGauge(name: label, labels: dimensions)
    }

    /// Makes (or dedupes to) the duration histogram for `label` + `dimensions`.
    public func makeTimer(label: String, dimensions: [(String, String)]) -> any TimerHandler {
        let buckets = durationHistogramBucketOverrides[label] ?? durationHistogramBuckets
        return registry.makeDurationHistogram(name: label, labels: dimensions, buckets: buckets)
    }

    /// Drops a destroyed counter from the exposition.
    public func destroyCounter(_ handler: any CounterHandler) {
        guard let counter = handler as? PrometheusCounter else {
            return
        }
        registry.unregister(counter: counter)
    }

    /// Drops a destroyed floating-point counter from the exposition.
    public func destroyFloatingPointCounter(_ handler: any FloatingPointCounterHandler) {
        guard let counter = handler as? PrometheusCounter else {
            return
        }
        registry.unregister(counter: counter)
    }

    /// Drops a destroyed recorder (gauge or value histogram) from the exposition.
    public func destroyRecorder(_ handler: any RecorderHandler) {
        switch handler {
            case let gauge as PrometheusGauge:
                registry.unregister(gauge: gauge)
            case let histogram as PrometheusValueHistogram:
                registry.unregister(valueHistogram: histogram)
            default:
                break
        }
    }

    /// Drops a destroyed meter from the exposition.
    public func destroyMeter(_ handler: any MeterHandler) {
        guard let gauge = handler as? PrometheusGauge else {
            return
        }
        registry.unregister(gauge: gauge)
    }

    /// Drops a destroyed timer from the exposition.
    public func destroyTimer(_ handler: any TimerHandler) {
        guard let histogram = handler as? PrometheusDurationHistogram else {
            return
        }
        registry.unregister(durationHistogram: histogram)
    }
}
