//
//  HandlerExecutionGate.swift
//  HTTPServer
//
//  The decision behind ``HandlerExecutionPolicy/adaptive(threshold:)`` (audit CR-F7): per route, is
//  this handler cheap enough to keep running inline on the connection's reactor?
//
//  Built entirely out of seams that already existed, which is why it needs no timing infrastructure
//  of its own and gets a deterministic test clock for free:
//
//    * ``MonotonicNowProvider`` — monotonic nanoseconds, never the wall clock, so a measurement
//      cannot come out negative because someone stepped the system time. A test injects
//      `TestClock().nowProvider` and pins every instant.
//    * ``RollingWindow`` — the same rolling-interval primitive the HTTP/2 Rapid Reset (CVE-2023-44487)
//      and HTTP/3 reset budgets measure their rates against.
//    * ``SharedBoundedLRU`` — a hard-bounded, sharded map. Bounding matters even though route keys
//      are not attacker-chosen: a long-lived process that hot-reloads its routing table mints a fresh
//      ``RouterIdentity`` each time, so an unbounded map would accumulate one generation of dead
//      route keys per reload (CWE-401/CWE-770). Overflow simply evicts, and an evicted route
//      re-measures from scratch on its next request.
//
//  THE RULE, stated once so it cannot drift from the tests:
//
//      A route hops when the PREVIOUS evaluation window contained a handler run longer than the
//      threshold, or when the CURRENT window has already seen one. A route with no measurement runs
//      inline.
//
//  The first clause is deliberate hysteresis. Without it a single fast request would erase the
//  evidence of a slow one and the route would flap between executors request by request, which costs
//  more than either decision. With it, a route that becomes cheap again returns to the inline path
//  after one whole quiet window, and a route that becomes expensive leaves the reactor on its very
//  next request.
//
//  NOT A LOCK ON PROTOCOL STATE. This is the audit's own distinction: no lock may guard the reactor's
//  connection, parse or protocol state, and none is added there. Service-time statistics are shared
//  across connections by definition, so they need synchronization; it is the package's existing
//  sharded-mutex primitive, it is touched only on the opt-in `.adaptive` path, and it is never held
//  across an `await`.
//

internal import HTTPConcurrency

/// Decides, per route, whether to run a handler off the connection's reactor.
///
/// Constructed only for ``HandlerExecutionPolicy/adaptive(threshold:)``; the fixed policies answer
/// without consulting anything and never allocate this.
final class HandlerExecutionGate: Sendable {
    /// How long one evaluation window lasts.
    ///
    /// A second is long enough that a route serving any real traffic contributes many samples to a
    /// window, and short enough that a route which changes cost is re-judged promptly. It is not
    /// configurable: it is the resolution of a hysteresis rule, not a tuning knob, and exposing it
    /// would invite a value short enough to reintroduce the flapping the rule exists to prevent.
    static let evaluationInterval: Duration = .seconds(1)

    /// How many distinct routes are tracked before the least recently used is dropped.
    ///
    /// Comfortably above any routing table this package benchmarks (the routing suite tops out at
    /// 1,000 routes) while still being a hard ceiling across hot reloads.
    private static let trackedRoutes = 4_096

    /// One route's verdict and the evidence behind it.
    private struct Record: Sendable {
        /// The window whose rollovers retire the verdict.
        var window: RollingWindow
        /// The decision in force right now.
        var hops: Bool
        /// Whether the current window has already seen a run over the threshold.
        var exceeded: Bool
    }

    private let thresholdNanoseconds: MonotonicNanoseconds
    private let intervalNanoseconds: MonotonicNanoseconds
    private let now: MonotonicNowProvider
    private let records: SharedBoundedLRU<RouteExecutionKey, Record>

    /// Creates a gate that hops a route once a handler run exceeds `threshold`.
    ///
    /// `now` is the injection seam: production takes the live monotonic clock, and a test passes a
    /// ``TestClock`` provider so window rollovers happen exactly when it says.
    init(threshold: Duration, now: @escaping MonotonicNowProvider = LiveMonotonicClock.now) {
        thresholdNanoseconds = threshold.monotonicNanoseconds
        intervalNanoseconds = Self.evaluationInterval.monotonicNanoseconds
        self.now = now
        records = SharedBoundedLRU(capacity: Self.trackedRoutes, shards: 8)
    }

    deinit {
        // No teardown beyond ARC; the sharded map releases with the instance.
    }

    /// The monotonic instant to time a handler run from and to.
    func timestamp() -> MonotonicNanoseconds {
        now()
    }

    /// Whether `key` should run off the reactor right now.
    ///
    /// Reads the verdict without advancing the window. A route that has been idle for longer than a
    /// window therefore serves one request on a stale verdict before ``record(_:for:)`` rolls it
    /// over — one request, self-correcting, and cheaper than taking the lock twice for a mutation
    /// that a request with no sample to contribute cannot justify.
    func hops(_ key: RouteExecutionKey) -> Bool {
        records.withShard(for: key) { $0.value(forKey: key)?.hops ?? false }
    }

    /// Files one handler run of `elapsed` nanoseconds against `key`, updating its verdict.
    func record(_ elapsed: MonotonicNanoseconds, for key: RouteExecutionKey) {
        let instant = now()
        let exceeded = elapsed > thresholdNanoseconds
        records.withShard(for: key) { map in
            var entry =
                map.value(forKey: key)
                ?? Record(
                    window: RollingWindow(start: instant, interval: intervalNanoseconds),
                    hops: false,
                    exceeded: false
                )
            if entry.window.rolledOver(at: instant) {
                // The closing window's evidence becomes the new window's verdict.
                entry.hops = entry.exceeded
                entry.exceeded = false
            }
            if exceeded {
                entry.exceeded = true
                entry.hops = true
            }
            _ = map.insert(entry, forKey: key)
        }
    }
}
