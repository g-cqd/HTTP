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
    /// Only a **request** stream can be armed (RFC 9114 §4.1 / RFC 9000 §2.1 — client-initiated
    /// bidirectional). The control and QPACK streams are long-lived by design (§6.2): they stay open
    /// for the connection's life and are idle whenever no settings or table updates flow, so a read
    /// budget aimed at a half-sent request reaps them — and with them the healthy connection. The
    /// refusal lives here, not at the call sites, so the table *cannot* come to hold a stream whose
    /// lapse would be reset as if it were a request.
    func armHTTP3(
        _ id: QUICStreamID,
        phase: HTTP3StreamPhase,
        on deadlines: HTTP3StreamDeadlines<C.Instant>
    ) {
        guard id.kind == .clientBidirectional else {
            return
        }
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
        registry: HTTP3StreamRegistry,
        engine: Engine,
        quic: any QUICConnection
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
            await reapLapsedHTTP3(
                deadlines: deadlines, registry: registry, engine: engine, quic: quic
            )
        }
    }

    /// Resets each stream whose deadline has passed, untracking it everywhere.
    ///
    /// The reset is what unblocks the stream's parked `receive` — a QUIC stream reset tears the
    /// underlying transport stream down, so its task unwinds instead of staying parked forever.
    ///
    /// It goes through ``resetHTTP3Stream(_:errorCode:registry:engine:quic:)`` so the *engine* is
    /// retired too (audit REG-3). Resetting only the writer and the registry entry left the sans-I/O
    /// engine holding every reaped stream's parser, QPACK and body state, and charged nothing against
    /// the RFC 9114 §8.1 reset budget — so a peer could repeat the abandonment for free and grow the
    /// connection's retained state without bound. On the deadline path of all places.
    private func reapLapsedHTTP3(
        deadlines: HTTP3StreamDeadlines<C.Instant>,
        registry: HTTP3StreamRegistry,
        engine: Engine,
        quic: any QUICConnection
    ) async {
        for lapse in deadlines.takeLapsed(at: clock.now) {
            await resetHTTP3Stream(
                lapse.streamID,
                errorCode: lapse.phase.errorCode,
                registry: registry,
                engine: engine,
                quic: quic
            )
        }
    }
}
