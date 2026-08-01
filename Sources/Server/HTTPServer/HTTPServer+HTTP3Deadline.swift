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
    ///
    /// Two streams can never be armed, and both refusals live here rather than at the call sites, so
    /// the table *cannot* come to hold one however a future caller arms.
    ///
    /// A stream that is not client-initiated bidirectional (RFC 9114 §4.1 / RFC 9000 §2.1). The control
    /// and QPACK streams are long-lived by design (§6.2): they stay open for the connection's life and
    /// are idle whenever no settings or table updates flow, so a read budget aimed at a half-sent
    /// request reaps them — and with them the healthy connection.
    ///
    /// And a stream that is no longer registered, which is what "retired" means to this connection
    /// (R5-P0c). A serve loop can reach its next arm *after* something inside the batch it just handled
    /// gave the stream up — a refused Extended CONNECT (RFC 9220 §3), a refused routed batch — and
    /// re-arming there leaves a timer running for a stream nothing will ever disarm again. Retirement
    /// drops the registry entry, so consulting it is what makes the disarm final.
    func armHTTP3(
        _ id: QUICStreamID,
        phase: HTTP3StreamPhase,
        in scope: HTTP3ConnectionScope
    ) {
        guard id.kind == .clientBidirectional, scope.registry.writer(for: id) != nil else {
            return
        }
        let budget = phase == .header ? limits.headerReadTimeout : limits.idleTimeout
        scope.deadlines.arm(id, until: clock.now.advanced(by: budget), phase: phase)
    }

    /// The connection's deadline watchdog: reset every request stream whose read deadline lapses.
    ///
    /// Sleeps to the earliest armed instant; with nothing armed it naps the shortest read-deadline
    /// knob and re-checks, the same shape ``runIdleWatchdog(_:)`` uses for HTTP/1.1 — so a deadline
    /// armed during the nap is still enforced near its intended bound. Returns when the connection's
    /// serving is cancelled.
    func runHTTP3DeadlineWatchdog(in scope: HTTP3ConnectionScope) async {
        while !Task.isCancelled {
            guard let next = scope.deadlines.earliest() else {
                let nap = min(limits.headerReadTimeout, limits.idleTimeout, limits.keepAliveTimeout)
                try? await clock.sleep(for: nap, tolerance: nil)
                continue
            }
            if clock.now < next {
                try? await clock.sleep(until: next, tolerance: nil)
            }
            await reapLapsedHTTP3(in: scope)
        }
    }

    /// Resets each stream whose deadline has passed, untracking it everywhere.
    ///
    /// The reset is what unblocks the stream's parked `receive` — a QUIC stream reset tears the
    /// underlying transport stream down, so its task unwinds instead of staying parked forever.
    ///
    /// It goes through ``retireHTTP3Stream(_:errorCode:in:)`` so the *engine* is
    /// retired too (audit REG-3). Resetting only the writer and the registry entry left the sans-I/O
    /// engine holding every reaped stream's parser, QPACK and body state, and charged nothing against
    /// the RFC 9114 §8.1 reset budget — so a peer could repeat the abandonment for free and grow the
    /// connection's retained state without bound. On the deadline path of all places.
    private func reapLapsedHTTP3(in scope: HTTP3ConnectionScope) async {
        for lapse in scope.deadlines.takeLapsed(at: clock.now) {
            await retireHTTP3Stream(lapse.streamID, errorCode: lapse.phase.errorCode, in: scope)
        }
    }
}
