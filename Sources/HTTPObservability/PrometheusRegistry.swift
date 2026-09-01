//
//  PrometheusRegistry.swift
//  HTTPObservability
//
//  The in-house replacement for swift-prometheus' `PrometheusCollectorRegistry` (the last
//  non-apple/swiftlang package in the graph): metric families keyed by name, each holding one series
//  per label set, rendered in the text exposition format 0.0.4. Registration takes a `Mutex` (it runs
//  once per `Metrics.Counter`/`Timer` construction and dedupes to the existing series); the returned
//  metric objects own their hot paths lock-free (counters/gauges) or under their own single lock
//  (histograms), so the registry lock is never on an increment path.
//
//  Emission is DETERMINISTIC — families sorted by name, series sorted by their label key — unlike
//  swift-prometheus' dictionary-order output. The spec allows any order; a stable one makes the
//  exposition diffable and golden-testable.
//
//  A name registered as two different metric kinds (or a histogram re-registered with different
//  buckets) is a programming error and traps, matching swift-prometheus: the alternative is silently
//  exporting series that PromQL cannot aggregate.
//

internal import Synchronization

/// A registry of Prometheus collectors, rendered in the text exposition format 0.0.4.
public final class PrometheusRegistry: Sendable {
    private struct LabelsKey: Hashable, Sendable {
        let labels: [(String, String)]

        /// A deterministic series ordering key (`name=value,…` over the raw labels).
        var sortKey: String {
            labels.map { "\($0.0)=\($0.1)" }.joined(separator: ",")
        }

        static func == (lhs: Self, rhs: Self) -> Bool {
            guard lhs.labels.count == rhs.labels.count else {
                return false
            }
            return zip(lhs.labels, rhs.labels).allSatisfy { $0.0 == $1.0 && $0.1 == $1.1 }
        }

        func hash(into hasher: inout Hasher) {
            for (name, value) in labels {
                hasher.combine(name)
                hasher.combine(value)
            }
        }
    }

    private enum Family: Sendable {
        case counters([LabelsKey: PrometheusCounter], help: String)
        case gauges([LabelsKey: PrometheusGauge], help: String)
        case durationHistograms(
            [LabelsKey: PrometheusDurationHistogram], buckets: [Duration], help: String
        )
        case valueHistograms([LabelsKey: PrometheusValueHistogram], buckets: [Double], help: String)
    }

    private let families = Mutex<[String: Family]>([:])

    /// Creates an empty registry.
    public init() {
        // Nothing beyond the mutex's defaults.
    }

    deinit {
        // Nothing beyond ARC.
    }

    // MARK: - Making collectors

    /// The counter for `name` + `labels`, created on first use (`help` is fixed at first creation).
    public func makeCounter(
        name: String,
        labels: [(String, String)] = [],
        help: String = ""
    ) -> PrometheusCounter {
        let name = PrometheusExposition.sanitizedMetricName(name)
        let labels = PrometheusExposition.sanitizedLabels(labels)
        let key = LabelsKey(labels: labels)
        return families.withLock { store in
            var series: [LabelsKey: PrometheusCounter] = [:]
            var familyHelp = help
            switch store[name] {
                case nil:
                    break
                case .counters(let existing, let existingHelp):
                    if let counter = existing[key] {
                        return counter
                    }
                    series = existing
                    familyHelp = existingHelp
                default:
                    preconditionFailure(
                        "metric '\(name)' is already registered as a different kind"
                    )
            }
            let counter = PrometheusCounter(name: name, labels: labels)
            series[key] = counter
            store[name] = .counters(series, help: familyHelp)
            return counter
        }
    }

    /// The gauge for `name` + `labels`, created on first use (`help` is fixed at first creation).
    public func makeGauge(
        name: String,
        labels: [(String, String)] = [],
        help: String = ""
    ) -> PrometheusGauge {
        let name = PrometheusExposition.sanitizedMetricName(name)
        let labels = PrometheusExposition.sanitizedLabels(labels)
        let key = LabelsKey(labels: labels)
        return families.withLock { store in
            var series: [LabelsKey: PrometheusGauge] = [:]
            var familyHelp = help
            switch store[name] {
                case nil:
                    break
                case .gauges(let existing, let existingHelp):
                    if let gauge = existing[key] {
                        return gauge
                    }
                    series = existing
                    familyHelp = existingHelp
                default:
                    preconditionFailure(
                        "metric '\(name)' is already registered as a different kind"
                    )
            }
            let gauge = PrometheusGauge(name: name, labels: labels)
            series[key] = gauge
            store[name] = .gauges(series, help: familyHelp)
            return gauge
        }
    }

    /// The duration histogram for `name` + `labels`, created on first use.
    ///
    /// `buckets` are sorted and deduplicated; the FIRST registration under `name` fixes them (and
    /// `help`) for the whole family — re-registering with different buckets traps.
    public func makeDurationHistogram(
        name: String,
        labels: [(String, String)] = [],
        buckets: [Duration],
        help: String = ""
    ) -> PrometheusDurationHistogram {
        let name = PrometheusExposition.sanitizedMetricName(name)
        let labels = PrometheusExposition.sanitizedLabels(labels)
        let key = LabelsKey(labels: labels)
        var bounds = Array(Set(buckets)).sorted()
        return families.withLock { store in
            var series: [LabelsKey: PrometheusDurationHistogram] = [:]
            var familyHelp = help
            switch store[name] {
                case nil:
                    break
                case .durationHistograms(let existing, let storedBounds, let existingHelp):
                    if let histogram = existing[key] {
                        return histogram
                    }
                    precondition(
                        storedBounds == bounds,
                        "histogram '\(name)' is already registered with different buckets"
                    )
                    series = existing
                    bounds = storedBounds
                    familyHelp = existingHelp
                default:
                    preconditionFailure(
                        "metric '\(name)' is already registered as a different kind"
                    )
            }
            let histogram = PrometheusDurationHistogram(name: name, labels: labels, buckets: bounds)
            series[key] = histogram
            store[name] = .durationHistograms(series, buckets: bounds, help: familyHelp)
            return histogram
        }
    }

    /// The value histogram for `name` + `labels`, created on first use.
    ///
    /// `buckets` are sorted, deduplicated, and restricted to finite bounds (`+Inf` is implicit); the
    /// FIRST registration under `name` fixes them (and `help`) for the whole family — re-registering
    /// with different buckets traps.
    public func makeValueHistogram(
        name: String,
        labels: [(String, String)] = [],
        buckets: [Double],
        help: String = ""
    ) -> PrometheusValueHistogram {
        let name = PrometheusExposition.sanitizedMetricName(name)
        let labels = PrometheusExposition.sanitizedLabels(labels)
        let key = LabelsKey(labels: labels)
        var bounds = Array(Set(buckets.filter(\.isFinite))).sorted()
        return families.withLock { store in
            var series: [LabelsKey: PrometheusValueHistogram] = [:]
            var familyHelp = help
            switch store[name] {
                case nil:
                    break
                case .valueHistograms(let existing, let storedBounds, let existingHelp):
                    if let histogram = existing[key] {
                        return histogram
                    }
                    precondition(
                        storedBounds == bounds,
                        "histogram '\(name)' is already registered with different buckets"
                    )
                    series = existing
                    bounds = storedBounds
                    familyHelp = existingHelp
                default:
                    preconditionFailure(
                        "metric '\(name)' is already registered as a different kind"
                    )
            }
            let histogram = PrometheusValueHistogram(name: name, labels: labels, buckets: bounds)
            series[key] = histogram
            store[name] = .valueHistograms(series, buckets: bounds, help: familyHelp)
            return histogram
        }
    }

    // MARK: - Unregistering (the swift-metrics `destroy` seam)

    /// Removes `counter` (identity-matched) from future expositions.
    func unregister(counter: PrometheusCounter) {
        families.withLock { store in
            guard case .counters(var series, let help) = store[counter.name],
                series[LabelsKey(labels: counter.labels)] === counter
            else {
                return
            }
            series.removeValue(forKey: LabelsKey(labels: counter.labels))
            store[counter.name] = series.isEmpty ? nil : .counters(series, help: help)
        }
    }

    /// Removes `gauge` (identity-matched) from future expositions.
    func unregister(gauge: PrometheusGauge) {
        families.withLock { store in
            guard case .gauges(var series, let help) = store[gauge.name],
                series[LabelsKey(labels: gauge.labels)] === gauge
            else {
                return
            }
            series.removeValue(forKey: LabelsKey(labels: gauge.labels))
            store[gauge.name] = series.isEmpty ? nil : .gauges(series, help: help)
        }
    }

    /// Removes `histogram` (identity-matched) from future expositions.
    func unregister(durationHistogram histogram: PrometheusDurationHistogram) {
        families.withLock { store in
            guard
                case .durationHistograms(var series, let buckets, let help) = store[histogram.name],
                series[LabelsKey(labels: histogram.labels)] === histogram
            else {
                return
            }
            series.removeValue(forKey: LabelsKey(labels: histogram.labels))
            store[histogram.name] =
                series.isEmpty ? nil : .durationHistograms(series, buckets: buckets, help: help)
        }
    }

    /// Removes `histogram` (identity-matched) from future expositions.
    func unregister(valueHistogram histogram: PrometheusValueHistogram) {
        families.withLock { store in
            guard case .valueHistograms(var series, let buckets, let help) = store[histogram.name],
                series[LabelsKey(labels: histogram.labels)] === histogram
            else {
                return
            }
            series.removeValue(forKey: LabelsKey(labels: histogram.labels))
            store[histogram.name] =
                series.isEmpty ? nil : .valueHistograms(series, buckets: buckets, help: help)
        }
    }

    // MARK: - Emitting

    /// Appends the whole exposition — families sorted by name, series by label key — to `buffer`.
    public func emit(into buffer: inout [UInt8]) {
        let orderedFamilies = families.withLock { store in
            store.sorted { $0.key < $1.key }
        }
        for (name, family) in orderedFamilies {
            switch family {
                case .counters(let series, let help):
                    PrometheusExposition.writeHeader(
                        name: name, type: "counter", help: help, into: &buffer
                    )
                    for counter in Self.ordered(series) {
                        counter.emit(into: &buffer)
                    }
                case .gauges(let series, let help):
                    PrometheusExposition.writeHeader(
                        name: name, type: "gauge", help: help, into: &buffer
                    )
                    for gauge in Self.ordered(series) {
                        gauge.emit(into: &buffer)
                    }
                case .durationHistograms(let series, _, let help):
                    PrometheusExposition.writeHeader(
                        name: name, type: "histogram", help: help, into: &buffer
                    )
                    for histogram in Self.ordered(series) {
                        histogram.emit(into: &buffer)
                    }
                case .valueHistograms(let series, _, let help):
                    PrometheusExposition.writeHeader(
                        name: name, type: "histogram", help: help, into: &buffer
                    )
                    for histogram in Self.ordered(series) {
                        histogram.emit(into: &buffer)
                    }
            }
        }
    }

    /// The series of one family in deterministic (label-key) order.
    private static func ordered<Metric>(_ series: [LabelsKey: Metric]) -> [Metric] {
        series.sorted { $0.key.sortKey < $1.key.sortKey }.map(\.value)
    }
}
