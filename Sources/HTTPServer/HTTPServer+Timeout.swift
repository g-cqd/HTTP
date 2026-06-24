//
//  HTTPServer+Timeout.swift
//  HTTPServer
//
//  Per-connection idle / Slowloris deadline. ONE background watchdog task per connection shares a
//  deadline with the serve loop: the loop ``IdleDeadline/arm(_:)``s it just before each blocking
//  receive and ``IdleDeadline/disarm()``s it after, and the watchdog closes the connection if the
//  deadline lapses (RFC 9112 §9.3 defenses). This replaces a `withThrowingTaskGroup` + `clock.sleep`
//  on *every* read — which a profiler showed was the server's single biggest per-request cost
//  (200k+ task-group creations/sec at 100k req/s) — with one task group + one timer per *connection*.
//

internal import HTTPCore
internal import HTTPTransport
internal import Synchronization

/// A per-connection deadline shared between the serve loop and its single watchdog task.
///
/// `Instant` is the server clock's instant type. All access is serialized by a `Mutex`, so the loop
/// (arming/disarming on its task) and the watchdog (reading on another) never race.
final class IdleDeadline<Instant: Comparable & Sendable>: Sendable {
    private struct State {
        var target: Instant?  // when the current receive must finish; nil between reads
        var lapsed = false  // the watchdog fired: the read ended on a timeout, not a peer EOF
    }

    private let state = Mutex(State())

    /// Arms the deadline before a blocking receive (the receive must complete by `instant`).
    func arm(_ instant: Instant) { state.withLock { $0.target = instant } }

    /// Disarms after a receive returns, so the (fast) processing between reads is not timed.
    func disarm() { state.withLock { $0.target = nil } }

    /// Records that the deadline lapsed (the serve loop reads this to report a clean idle close).
    func markLapsed() { state.withLock { $0.lapsed = true } }

    var target: Instant? { state.withLock(\.target) }

    /// Whether the read ended on a deadline lapse (so the read loop reports a clean idle close, not a
    /// truncation error).
    var hasLapsed: Bool { state.withLock(\.lapsed) }

    deinit {
        // No teardown beyond ARC.
    }
}

extension HTTPServer {
    /// Serves one connection with a single background idle watchdog.
    ///
    /// `body` (the whole serve loop) and the watchdog race in one task group; whichever finishes first
    /// cancels the other. `body` arms/disarms the ``IdleDeadline`` around each receive; when the
    /// deadline lapses the watchdog returns, and cancelling `body` unblocks its parked receive through
    /// the connection's cancellation handler — exactly the mechanism the per-read `withTimeout` used,
    /// but with one task group + one timer per *connection* instead of per *read*.
    func withIdleWatchdog(
        _: any TransportConnection,
        _ body: @escaping @Sendable (IdleDeadline<C.Instant>) async -> Void
    ) async {
        let deadline = IdleDeadline<C.Instant>()
        await withTaskGroup(of: Void.self) { group in
            group.addTask { await body(deadline) }
            group.addTask { await self.runIdleWatchdog(deadline) }
            // First to finish wins (serve ended, or the deadline lapsed); cancel the loser — a parked
            // receive unblocks via its cancellation handler.
            await group.next()
            group.cancelAll()
        }
    }

    /// The watchdog: return (marking the lapse) once the armed deadline passes.
    ///
    /// Sleeps to the armed deadline; while disarmed, naps (bounded) and re-checks. Returns on a lapse,
    /// or exits when the serve loop cancels it.
    private func runIdleWatchdog(_ deadline: IdleDeadline<C.Instant>) async {
        while !Task.isCancelled {
            if let target = deadline.target {
                if clock.now >= target {
                    deadline.markLapsed()
                    return
                }
                try? await clock.sleep(until: target, tolerance: nil)
            }
            else {
                // Between reads the deadline is briefly nil; nap the SHORTEST read-deadline knob (not
                // just keepAliveTimeout) and re-check, so a header-phase deadline (headerReadTimeout)
                // armed during the nap is still enforced near its intended bound, not up to 15s late.
                let nap = min(limits.headerReadTimeout, limits.idleTimeout, limits.keepAliveTimeout)
                try? await clock.sleep(for: nap, tolerance: nil)
            }
        }
    }
}
