//
//  InMemorySessionStore.swift
//  HTTPServer
//
//  A process-local ``SessionStore``: a Mutex-guarded map of session id → last-seen monotonic timestamp,
//  with a sliding TTL (each ``validate(_:)`` refreshes it) so an idle session expires server-side, and
//  explicit ``revoke(_:)`` for logout. Time is an injected ``MonotonicNowProvider`` (never the wall
//  clock), so a test pins expiry with no real waiting. The map is bounded: when it grows past a cap, a
//  ``register(_:)`` first drops expired ids, so a churn of sessions cannot grow it without bound
//  (CWE-400). For a single process; back a multi-process deployment with a shared store instead.
//

public import HTTPConcurrency

private import Synchronization

/// An in-memory ``SessionStore`` with a sliding TTL and a bounded session map.
public final class InMemorySessionStore: SessionStore {
    /// Mutex-guarded state in a class because `Mutex` is non-copyable (mirrors ``RateLimitMiddleware``).
    private final class State: Sendable {
        let sessions = Mutex<[String: MonotonicNanoseconds]>([:])

        deinit {
            // No teardown beyond ARC; the Mutex releases with the instance.
        }
    }

    private let ttlNanos: MonotonicNanoseconds
    private let maxSessions: Int
    private let now: MonotonicNowProvider
    private let state = State()

    deinit {
        // No teardown beyond ARC; the State's Mutex releases with the instance.
    }

    /// Creates the store: a session idle longer than `ttl` expires; `maxSessions` bounds the map; `now`
    /// is injectable for tests (defaults to the monotonic clock).
    public init(
        ttl: Duration = .seconds(86_400),
        maxSessions: Int = 1_000_000,
        now: @escaping MonotonicNowProvider = LiveMonotonicClock.now
    ) {
        self.ttlNanos = ttl.monotonicNanoseconds
        self.maxSessions = max(1, maxSessions)
        self.now = now
    }

    /// Whether `id` is live (within the sliding TTL), refreshing its last-seen time; drops it if expired.
    public func validate(_ id: String) async -> Bool {
        let instant = now()
        return state.sessions.withLock { sessions in
            guard let lastSeen = sessions[id], instant - lastSeen <= ttlNanos else {
                sessions[id] = nil  // expired or unknown — drop so the map stays tight
                return false
            }
            sessions[id] = instant  // slide the TTL
            return true
        }
    }

    /// Registers `id` as live now, first pruning expired ids when the map is at its cap.
    public func register(_ id: String) async {
        let instant = now()
        state.sessions.withLock { sessions in
            if sessions.count >= maxSessions {
                Self.prune(&sessions, at: instant, ttl: ttlNanos)
            }
            sessions[id] = instant
        }
    }

    /// Revokes `id` immediately (logout); a later ``validate(_:)`` returns `false`.
    public func revoke(_ id: String) async {
        state.sessions.withLock { $0[id] = nil }
    }

    /// Drops every session whose last-seen time is older than the TTL — bounding the map under churn.
    private static func prune(
        _ sessions: inout [String: MonotonicNanoseconds],
        at instant: MonotonicNanoseconds,
        ttl: MonotonicNanoseconds
    ) {
        for (id, lastSeen) in sessions where instant - lastSeen > ttl {
            sessions[id] = nil
        }
    }
}
