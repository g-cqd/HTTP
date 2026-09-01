//
//  RateLimitMiddleware.swift
//  HTTPServer
//
//  A per-client request-rate limiter (RFC 6585 §4 / CWE-770). Each client gets a ``RollingWindow``
//  budget; once the count in the current window exceeds the limit the request is refused with
//  `429 Too Many Requests` and a `Retry-After`, without reaching the responder. Time is an injected
//  ``MonotonicNowProvider`` (monotonic, never the wall clock), so a test pins it with no real waiting.
//
//  Two things here are load-bearing and were previously wrong.
//
//  *Who a client is* is now ``RateLimitIdentity`` — by default the verified transport peer, not the
//  `Host` header. See that type for why the old default was simultaneously a starvation bug for
//  honest clients and a free bypass for a hostile one.
//
//  *How many clients can be tracked* is now a hard bound rather than an aspiration. The old admit
//  path did "if the map is full, drop the idle entries" and then inserted unconditionally; when every
//  entry was live — precisely what a flood produces — nothing was dropped and the map grew without
//  limit (CWE-400). The table is a ``SharedBoundedLRU`` with ``BoundedLRU/Overflow/reject``, so
//  admission and capacity are decided together under one lock, and a client the table has no room for
//  is refused with 429 instead of allocated for. Fail-closed on purpose: allocating on behalf of an
//  unknown identity is the attack, and evicting instead would be worse still — it would let an
//  attacker push a legitimate client out of the table and reset its budget at will.
//
//  *How long the window is* is now repaired too (R5-VAL). A `RollingWindow` of zero — or of a negative
//  duration — reports "rolled over" on every single call, so the budget was zeroed before each request
//  and `count <= limit` was always true: one mistyped `per:` disabled rate limiting outright while the
//  middleware went on reporting itself installed (CWE-1284, and it removes a control that exists for
//  CWE-770). The repair is a *substitution*, not a clamp, and that distinction is the whole point.
//  Every other knob here clamps with `max(1, ·)` because for those the nearest legal value is also the
//  strictest one. A window has the opposite geometry: the nearest legal value above zero is one
//  nanosecond, which is the most permissive window there is and leaves the control just as disabled as
//  before — a clamp that launders the bug instead of fixing it. `HTTPLimits.Bounds` already names this
//  exact case for `acceptResumeRatio` and NaN: when no clamp target preserves the property the field
//  was configured for, substitute the documented default. So a non-positive window becomes
//  ``substitutedInterval``, which is also the floor `retryAfterSeconds` already used, so the window
//  enforced and the `Retry-After` advertised agree. A *positive* window is never touched, however
//  short: a deliberate 100 ms budget is a real configuration, and only the incoherent case is repaired.
//

public import HTTPConcurrency
public import HTTPCore

/// Refuses a client that exceeds `limit` requests per window with `429 Too Many Requests` (RFC 6585).
public struct RateLimitMiddleware: HTTPMiddleware {
    /// One client's budget: when its window started, and how much of it has been spent.
    private struct Bucket: Sendable {
        var window: RollingWindow
        var count: Int
    }

    /// How many of the most-idle budgets an admission sweeps before giving up on making room.
    ///
    /// Bounded so no single request is charged an O(*n*) scan of the whole table: the sweep is
    /// amortized across admissions, and a table of genuinely live clients simply stays full.
    private static let reclaimScan = 16

    /// The window substituted for a non-positive `per:` interval (R5-VAL).
    ///
    /// One second: the smallest window this type can also advertise honestly, since `Retry-After` is
    /// expressed in whole seconds (RFC 9110 §10.2.3) and already floored there. See the file comment
    /// for why a non-positive window is *substituted* rather than clamped to the nearest legal value.
    public static let substitutedInterval = Duration.seconds(1)

    private let limit: Int
    private let intervalNanos: MonotonicNanoseconds
    private let retryAfterSeconds: Int
    private let identity: RateLimitIdentity
    private let now: MonotonicNowProvider
    private let clients: SharedBoundedLRU<String, Bucket>

    /// Creates the limiter: at most `limit` requests `per` window, per ``RateLimitIdentity``.
    ///
    /// `maxTrackedClients` is a hard cap on the tracking table — once it is full, a client not
    /// already in it is refused. Size it above the number of distinct clients genuinely expected
    /// within one window, or legitimate newcomers are turned away during a flood. `shards` trades a
    /// little memory for lock contention; `now` is injectable for tests.
    ///
    /// A non-positive `interval` is replaced by ``substitutedInterval`` rather than clamped to the
    /// nearest legal duration, because the nearest legal duration is the *most permissive* window and
    /// would leave rate limiting disabled — see the file comment (R5-VAL).
    public init(
        limit: Int,
        per interval: Duration,
        identity: RateLimitIdentity = .peerAddress(),
        maxTrackedClients: Int = 100_000,
        shards: Int = 8,
        now: @escaping MonotonicNowProvider = LiveMonotonicClock.now
    ) {
        let window = interval > .zero ? interval : Self.substitutedInterval
        self.limit = max(1, limit)
        self.intervalNanos = window.monotonicNanoseconds
        // Derived from the repaired window, so the advertised retry never outruns the enforced one.
        self.retryAfterSeconds = max(1, Int(window.components.seconds))
        self.identity = identity
        self.now = now
        self.clients = SharedBoundedLRU(
            capacity: max(1, maxTrackedClients),
            overflow: .reject,
            shards: max(1, shards)
        )
    }

    /// How many clients the table is tracking — by construction never above `maxTrackedClients`.
    var trackedClients: Int {
        clients.totalCount
    }

    /// Admits the request, or refuses it with `429` + `Retry-After` when the client is over budget.
    public func respond(
        to request: HTTPRequest,
        body: RequestBody,
        context: RequestContext,
        next: any HTTPResponder
    ) async -> ServerResponse {
        guard admit(identity.key(for: request, context: context)) else {
            var head = HTTPResponse(status: .tooManyRequests)
            _ = head.headerFields.setValue(String(retryAfterSeconds), for: .retryAfter)
            return ServerResponse(head)
        }
        return await next.respond(to: request, body: body, context: context)
    }

    /// Whether `client` is within budget for the current window; counts this request either way.
    private func admit(_ client: String) -> Bool {
        let instant = now()
        return clients.withShard(for: client) { budgets in
            spend(for: client, in: &budgets, at: instant)
        }
    }

    /// The whole admission decision, inside one shard lock: bump a tracked budget, or take a slot.
    ///
    /// One critical section on purpose — splitting "is there room?" from "insert" across two of them
    /// is exactly how the previous implementation exceeded its own cap.
    private func spend(
        for client: String,
        in budgets: inout BoundedLRU<String, Bucket>,
        at instant: MonotonicNanoseconds
    ) -> Bool {
        let bumped = budgets.withValue(forKey: client) { bucket -> Bool in
            if bucket.window.rolledOver(at: instant) {
                bucket.count = 0
            }
            bucket.count += 1
            return bucket.count <= limit
        }
        if let bumped {
            return bumped
        }
        budgets.reclaim(scanning: Self.reclaimScan) { _, bucket in
            var window = bucket.window
            return window.rolledOver(at: instant)  // idle: its window has already elapsed
        }
        let fresh = Bucket(
            window: RollingWindow(start: instant, interval: intervalNanos),
            count: 1
        )
        guard case .rejected = budgets.insert(fresh, forKey: client) else {
            return true
        }
        return false  // no room to track this client — refuse rather than allocate for it
    }
}
