//
//  InMemorySessionStore.swift
//  HTTPServer
//
//  A process-local ``SessionStore``: session id → last-seen monotonic timestamp, with a sliding TTL
//  (each ``validate(_:)`` refreshes it) so an idle session expires server-side, and explicit
//  ``revoke(_:)`` for logout. Time is an injected ``MonotonicNowProvider`` (never the wall clock), so
//  a test pins expiry with no real waiting. For a single process; back a multi-process deployment
//  with a shared store instead.
//
//  The map is a ``SharedBoundedLRU``, which is a real bound rather than the one this type used to
//  claim. The old `register` did "if the map is at its cap, drop the expired ids" and then inserted
//  unconditionally — so when nothing had expired, which is exactly the case a session flood produces,
//  it dropped nothing and inserted anyway, and the map grew past `maxSessions` without limit
//  (CWE-400). It now reclaims a bounded slice of the most-idle ids and, if that is not enough, evicts
//  the least recently used.
//
//  Eviction, not refusal, on purpose — the opposite of ``RateLimitMiddleware``'s admission table. A
//  refused registration would hand the client a session cookie the server had already forgotten, so
//  the very next request would fail validation and mint another, forever. Evicting the most idle
//  session logs somebody out early, which is recoverable; refusing is a livelock.
//
//  **This TTL is an idle timeout, not a lifetime** (audit R5-SEC2). Every ``validate(_:)`` slides it
//  forward, which is the correct behavior for "log out a user who walked away" and is exactly wrong as
//  an absolute bound: a session replayed once a minute stays live here forever, so a stolen cookie kept
//  warm never ages out on its own (CWE-613). The absolute cap is not this type's job and is not added
//  here — it lives in the expiry ``SessionMiddleware`` signs into the token, which is checked *before*
//  the store is consulted, so it bounds the stateless and the store-backed configuration alike. What
//  only a store can do it still does: revoke immediately, and time out an idle session early.
//

public import HTTPConcurrency

/// An in-memory ``SessionStore`` with a sliding TTL and a hard-bounded session map.
public final class InMemorySessionStore: SessionStore {
    /// How many of the most-idle sessions a registration sweeps before falling back to eviction.
    ///
    /// Bounded so no single registration is charged an O(*n*) scan of the whole map.
    private static let reclaimScan = 32

    private let ttlNanos: MonotonicNanoseconds
    private let now: MonotonicNowProvider
    private let sessions: SharedBoundedLRU<String, MonotonicNanoseconds>

    deinit {
        // No teardown beyond ARC; the sharded map releases with the instance.
    }

    /// Creates the store: a session idle longer than `ttl` expires; `maxSessions` bounds the map.
    ///
    /// `ttl` is an *idle* timeout — it slides forward on every ``validate(_:)``, so it bounds
    /// inactivity rather than total lifetime. The absolute lifetime comes from the expiry
    /// ``SessionMiddleware`` signs into the token (R5-SEC2).
    ///
    /// `shards` trades a little memory for lock contention, and `now` is injectable for tests
    /// (defaulting to the monotonic clock).
    public init(
        ttl: Duration = .seconds(86_400),
        maxSessions: Int = 1_000_000,
        shards: Int = 8,
        now: @escaping MonotonicNowProvider = LiveMonotonicClock.now
    ) {
        self.ttlNanos = ttl.monotonicNanoseconds
        self.now = now
        self.sessions = SharedBoundedLRU(capacity: max(1, maxSessions), shards: max(1, shards))
    }

    /// How many sessions are held — by construction never above `maxSessions`.
    public var count: Int {
        sessions.totalCount
    }

    /// Whether `id` is live (within the sliding TTL), refreshing its last-seen time.
    ///
    /// A hit also promotes the session to the most-recently-used end, so the eviction victim is
    /// genuinely the most idle one rather than merely the oldest to have registered.
    public func validate(_ id: String) async -> Bool {
        let instant = now()
        return sessions.withShard(for: id) { live in
            let alive = live.withValue(forKey: id) { lastSeen -> Bool in
                guard instant - lastSeen <= ttlNanos else {
                    return false
                }
                lastSeen = instant  // slide the TTL
                return true
            }
            guard alive == true else {
                live.removeValue(forKey: id)  // expired or unknown — drop so the map stays tight
                return false
            }
            return true
        }
    }

    /// Registers `id` as live now, reclaiming expired ids first and evicting the most idle if needed.
    public func register(_ id: String) async {
        let instant = now()
        sessions.withShard(for: id) { live in
            live.reclaim(scanning: Self.reclaimScan) { _, lastSeen in
                instant - lastSeen > ttlNanos
            }
            live.insert(instant, forKey: id)
        }
    }

    /// Revokes `id` immediately (logout); a later ``validate(_:)`` returns `false`.
    public func revoke(_ id: String) async {
        _ = sessions.withShard(for: id) { $0.removeValue(forKey: id) }
    }
}
