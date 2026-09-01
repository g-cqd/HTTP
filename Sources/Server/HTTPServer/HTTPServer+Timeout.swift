//
//  HTTPServer+Timeout.swift
//  HTTPServer
//
//  The server's ONE deadline watchdog shape, driving a connection's ``DeadlineWheel``.
//
//  Three shapes lived here and in HTTPServer+HTTP3Deadline.swift: `runIdleWatchdog` (the HTTP/1.1
//  connection-wide budget), `runLocalIdleWatchdog` (the HTTP/2 send budget and each streaming relay's
//  producer pull), and `runHTTP3DeadlineWatchdog` (the per-QUIC-stream read budgets). All three
//  duplicated the same two mistakes: they polled at `min(headerReadTimeout, idleTimeout,
//  keepAliveTimeout)` whenever nothing was armed, and — the correctness defect — they could not be
//  woken when an earlier deadline was armed while they slept, so a 15 s budget replacing a 60 s one was
//  enforced 45 s late (RFC 9112 §9.3 / RFC 9114 §4.1; CWE-400).
//
//  ``runDeadlineWatchdog(_:afterLapses:)`` fixes both: it parks with no wakeups at all while the wheel
//  is empty, and the wheel resumes it whenever an arm moves the minimum earlier.
//

internal import HTTPTransport

extension HTTPServer {
    /// Serves one connection with a single background deadline watchdog.
    ///
    /// `body` (the whole serve loop) and the watchdog race in one task group; whichever finishes first
    /// cancels the other. `body` arms/disarms the ``IdleDeadline`` around each receive; when the
    /// deadline lapses the watchdog returns, and cancelling `body` — a **child task**, so the
    /// serve-task-level `cancel()` handler never fires — unblocks its parked receive through the
    /// transport's own per-call cancellation handling (the `TransportConnection` receive contract: a
    /// cancelled receive tears the connection down and resumes promptly).
    ///
    /// The wheel handed to `body` is the connection's only one: HTTP/2 registers its send and relay
    /// deadlines in it (through ``IdleDeadline/wheel``) instead of standing up a watchdog task each,
    /// so an HTTP/2 connection carrying *n* streaming relays now costs one watchdog rather than
    /// `2 + n`.
    func withIdleWatchdog(
        _: any TransportConnection,
        _ body: @escaping @Sendable (IdleDeadline) async -> Void
    ) async {
        let wheel = DeadlineWheel()
        // The connection-wide budget is the one lapse that ends the connection, so it — and only it —
        // stops the watchdog, which is what makes `group.next()` return and cancel the serve loop.
        let deadline = IdleDeadline(in: wheel, escalation: .stopWatching)
        await withTaskGroup(of: Void.self) { group in
            group.addTask { await body(deadline) }
            group.addTask { [self] in await runDeadlineWatchdog(wheel) }
            // First to finish wins (serve ended, or the deadline lapsed); cancel the loser — a parked
            // receive unblocks via its cancellation handler.
            await group.next()
            group.cancelAll()
        }
    }

    /// Fires the deadlines of `wheel` as they lapse.
    ///
    /// Returns when a lapse asks it to stop, or when the task is cancelled.
    ///
    /// Sleeps to the wheel's earliest armed instant, racing that sleep against the wheel's own wake
    /// signal so an arm that moves the minimum earlier is enforced at the *new* instant. With nothing
    /// armed it parks on the same signal and consumes nothing — no polling nap, which is what the
    /// three watchdogs this replaced did between reads.
    ///
    /// `afterLapses` is the seam for escalation that must `await` (HTTP/3 retires a lapsed stream
    /// through its connection engine). It runs only on turns that actually fired, so a wake for a
    /// target the serve loop disarmed mid-sleep costs nothing.
    func runDeadlineWatchdog(
        _ wheel: DeadlineWheel,
        afterLapses: (@Sendable () async -> Void)? = nil
    ) async {
        while !Task.isCancelled {
            let next = wheel.earliest
            guard let next, deadlineNow >= next else {
                await parkWatchdog(until: next, on: wheel)
                continue
            }
            let firing = wheel.fireLapsed(at: deadlineNow)
            if !firing.isEmpty {
                await afterLapses?()
            }
            if firing.action == .stopWatching {
                return
            }
        }
    }

    /// Suspends until `next` arrives or something earlier is armed.
    ///
    /// The two-child group is the cost of racing a generic `Clock`'s `sleep` — which has no callback
    /// form — against the wheel's wake signal. It is paid once per timer expiry or early arm on ONE
    /// task per connection, where the previous design paid one whole watchdog task per *operation*
    /// plus a poll every `min(headerReadTimeout, idleTimeout, keepAliveTimeout)` while idle.
    private func parkWatchdog(until next: Duration?, on wheel: DeadlineWheel) async {
        guard let next else {
            await wheel.waitForArm(earlierThan: nil)
            return
        }
        await withTaskGroup(of: Void.self) { group in
            group.addTask { [self] in
                try? await clock.sleep(until: deadlineInstant(for: next), tolerance: nil)
            }
            group.addTask { await wheel.waitForArm(earlierThan: next) }
            await group.next()
            group.cancelAll()
        }
    }
}
