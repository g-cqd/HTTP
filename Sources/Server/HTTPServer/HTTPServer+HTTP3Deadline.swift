//
//  HTTPServer+HTTP3Deadline.swift
//  HTTPServer
//
//  The HTTP/3 per-stream read deadlines (audit addendum P0.5) — one watchdog per QUIC *connection*
//  serving every one of its request streams, rather than one task per stream.
//
//  The HTTP/1.1 path pays a single watchdog per connection (see HTTPServer+Timeout.swift, FIX #8);
//  doing it per QUIC stream would double the task count of the h3 hot path for a defense that is
//  almost never the thing that ends a stream. Instead the stream tasks arm and disarm a shared
//  ``HTTP3StreamDeadlines`` table around each blocking receive, and one watchdog sleeps until the
//  earliest armed instant, resets whatever has lapsed, and sleeps again — no periodic wakeup while
//  work is in flight.
//
//  Standards: the RFC 9112 §9.3 Slowloris defense applied to RFC 9114 §4.1 request streams; reset
//  codes from RFC 9114 §8.1. CWE-400.
//

internal import HTTP3
internal import HTTPCore
internal import HTTPTransport

extension HTTPServer {
    /// Arms the read deadline for `id` in `phase`, measured from now against the server's clock.
    ///
    /// The header phase gets ``HTTPLimits/headerReadTimeout`` (a stream that opens and never sends a
    /// complete HEADERS frame), the body phase ``HTTPLimits/idleTimeout`` (a stream that stalls
    /// between DATA frames, or never sends the FIN that ends the body).
    func armHTTP3(
        _ id: QUICStreamID,
        phase: HTTP3StreamPhase,
        on deadlines: HTTP3StreamDeadlines<C.Instant>
    ) {
        let budget = phase == .header ? limits.headerReadTimeout : limits.idleTimeout
        deadlines.arm(id, until: clock.now.advanced(by: budget), phase: phase)
    }

    /// The connection's deadline watchdog: reset every request stream whose read deadline lapses.
    ///
    /// Sleeps to the earliest armed instant; with nothing armed it naps the shortest read-deadline
    /// knob and re-checks, the same shape ``runIdleWatchdog(_:)`` uses for HTTP/1.1 — so a deadline
    /// armed during the nap is still enforced near its intended bound. Returns when the connection's
    /// serving is cancelled.
    func runHTTP3DeadlineWatchdog(
        deadlines: HTTP3StreamDeadlines<C.Instant>,
        registry: HTTP3StreamRegistry
    ) async {
        while !Task.isCancelled {
            guard let next = deadlines.earliest() else {
                let nap = min(limits.headerReadTimeout, limits.idleTimeout, limits.keepAliveTimeout)
                try? await clock.sleep(for: nap, tolerance: nil)
                continue
            }
            if clock.now < next {
                try? await clock.sleep(until: next, tolerance: nil)
            }
            reapLapsedHTTP3(deadlines: deadlines, registry: registry)
        }
    }

    /// Resets each stream whose deadline has passed, untracking it.
    ///
    /// The reset is what unblocks the stream's parked `receive` — a QUIC stream reset tears the
    /// underlying transport stream down, so its task unwinds instead of staying parked forever.
    private func reapLapsedHTTP3(
        deadlines: HTTP3StreamDeadlines<C.Instant>,
        registry: HTTP3StreamRegistry
    ) {
        for lapse in deadlines.takeLapsed(at: clock.now) {
            registry.writer(for: lapse.streamID)?.reset(errorCode: lapse.phase.errorCode)
            registry.retire(lapse.streamID)
        }
    }
}
