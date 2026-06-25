//
//  SpyMetrics.swift
//  HTTPServerTests
//
//  A recording HTTPMetrics sink: captures every (method, path, status, duration) the
//  MetricsMiddleware reports, so the observability seam can be asserted exactly.
//

import HTTPCore
import HTTPServer
import Synchronization

/// A recording ``HTTPMetrics`` sink that captures every metric for assertion.
final class SpyMetrics: HTTPMetrics {
    /// One captured metric.
    struct Record: Sendable {
        let method: HTTPMethod
        let path: String
        let status: HTTPStatus
        let duration: Duration
    }

    private let storage = Mutex<[Record]>([])

    /// Every metric recorded so far, in order.
    var records: [Record] { storage.withLock(\.self) }

    func record(method: HTTPMethod, path: String, status: HTTPStatus, duration: Duration) {
        storage.withLock {
            $0.append(Record(method: method, path: path, status: status, duration: duration))
        }
    }

    deinit {
        // No teardown beyond ARC.
    }
}
