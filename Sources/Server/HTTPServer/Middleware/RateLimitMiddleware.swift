//
//  RateLimitMiddleware.swift
//  HTTPServer
//
//  A per-client request-rate limiter (RFC 6585 §4 / CWE-770). Each client key gets a ``RollingWindow``
//  budget; once the count in the current window exceeds the limit the request is refused with
//  `429 Too Many Requests` and a `Retry-After`, without reaching the responder. Time is an injected
//  ``MonotonicNowProvider`` (monotonic, never the wall clock), so a test pins it with no real waiting.
//  The tracking map is Mutex-guarded and bounded: when it grows past a cap, rolled-over (idle) clients
//  are pruned, so a flood of distinct keys cannot grow it without bound (CWE-400).
//

public import HTTPConcurrency
public import HTTPCore
private import Synchronization

/// Refuses a client that exceeds `limit` requests per window with `429 Too Many Requests` (RFC 6585).
public struct RateLimitMiddleware: HTTPMiddleware {
    private struct Bucket {
        var window: RollingWindow
        var count: Int
    }

    /// Mutex-guarded tracking state (a class because `Mutex` is non-copyable; mirrors ``DateCache``).
    private final class Store: Sendable {
        let buckets = Mutex<[String: Bucket]>([:])

        deinit {
            // No teardown beyond ARC; the Mutex releases with the instance.
        }
    }

    private let limit: Int
    private let intervalNanos: MonotonicNanoseconds
    private let retryAfterSeconds: Int
    private let maxTrackedClients: Int
    private let key: @Sendable (HTTPRequest) -> String
    private let now: MonotonicNowProvider
    private let store = Store()

    /// Creates the limiter: at most `limit` requests `per` window, keyed by `key` (default: the
    /// request authority). `maxTrackedClients` bounds the tracking map; `now` is injectable for tests.
    public init(
        limit: Int,
        per interval: Duration,
        maxTrackedClients: Int = 100_000,
        key: @escaping @Sendable (HTTPRequest) -> String = { $0.effectiveAuthority ?? "" },
        now: @escaping MonotonicNowProvider = LiveMonotonicClock.now
    ) {
        self.limit = max(1, limit)
        self.intervalNanos = interval.monotonicNanoseconds
        self.retryAfterSeconds = max(1, Int(interval.components.seconds))
        self.maxTrackedClients = max(1, maxTrackedClients)
        self.key = key
        self.now = now
    }

    /// Admits the request, or refuses it with `429` + `Retry-After` when the client is over budget.
    public func respond(
        to request: HTTPRequest,
        body: RequestBody,
        context: RequestContext,
        next: any HTTPResponder
    ) async -> ServerResponse {
        guard admit(key(request)) else {
            var head = HTTPResponse(status: .tooManyRequests)
            _ = head.headerFields.setValue(String(retryAfterSeconds), for: .retryAfter)
            return ServerResponse(head)
        }
        return await next.respond(to: request, body: body, context: context)
    }

    /// Whether `client` is within budget for the current window; counts this request either way.
    private func admit(_ client: String) -> Bool {
        let instant = now()
        return store.buckets.withLock { buckets in
            if buckets.count >= maxTrackedClients {
                Self.prune(&buckets, at: instant)
            }
            var bucket =
                buckets[client]
                ?? Bucket(
                    window: RollingWindow(start: instant, interval: intervalNanos), count: 0
                )
            if bucket.window.rolledOver(at: instant) {
                bucket.count = 0
            }
            bucket.count += 1
            buckets[client] = bucket
            return bucket.count <= limit
        }
    }

    /// Drops clients whose window has rolled over (idle), bounding the map under a key flood.
    private static func prune(_ buckets: inout [String: Bucket], at instant: MonotonicNanoseconds) {
        for (client, bucket) in buckets {
            var bucket = bucket
            if bucket.window.rolledOver(at: instant) {
                buckets[client] = nil
            }
        }
    }
}
