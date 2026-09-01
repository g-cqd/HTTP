//
//  HTTPServer+HTTP2StallSweeper.swift
//  HTTPServer
//
//  The head-of-line consequence of consumption-gated flow control, bounded (2026-07-31 audit F2/F4,
//  ADR 0006).
//
//  Once WINDOW_UPDATE depends on the application rather than on arrival, a handler that stops reading
//  keeps its share of the connection's *shared* receive window shut, and every sibling stream on that
//  connection slows down with it. That is HTTP/2's own semantics — one connection, one window — and not
//  something a server can design away; what it must not be is unbounded, or a single wedged handler
//  becomes a connection-wide denial of service.
//
//  This task only decides WHEN to look. The decision itself is a pure function of byte progress
//  (``HTTP2ConnectionState/sweepStalls()``), which keeps it deterministic and lets a test drive the
//  `.sweepStalls` wakeup by hand instead of waiting on a clock.
//

internal import HTTPCore

extension HTTPServer {
    /// Yields a `.sweepStalls` wakeup every half a ``HTTPLimits/bodyConsumptionTimeout``.
    ///
    /// Half, because a stream is only reset after two consecutive sweeps see it holding credit with no
    /// consumption: sampling at half the budget makes the *time* to a reset land between one and two
    /// times the configured timeout, while the two-sample rule keeps a handler that merely happened to
    /// be between chunks when one sweep landed from being punished for it.
    ///
    /// Like every other local watchdog in this design it reports through the mailbox rather than acting
    /// itself, so the engine stays single-owner on the consumer.
    func runHTTP2StallSweeper(into continuation: AsyncStream<HTTP2Wakeup>.Continuation) async {
        let interval = limits.bodyConsumptionTimeout / 2
        guard interval > .zero else {
            return  // sweeping disabled
        }
        while !Task.isCancelled {
            do {
                try await clock.sleep(for: interval, tolerance: nil)
            }
            catch {
                return  // cancelled: the connection is going away
            }
            continuation.yield(.sweepStalls)
        }
    }
}
