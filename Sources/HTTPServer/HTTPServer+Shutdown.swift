//
//  HTTPServer+Shutdown.swift
//  HTTPServer
//
//  Graceful shutdown (RFC 9110 §7.6.1 / RFC 9113 §6.8): stop accepting, then let each in-flight
//  connection finish its current exchange before closing — HTTP/1 with `Connection: close`, HTTP/2
//  with a GOAWAY naming the last stream the connection will process. Kept out of HTTPServer.swift so
//  the runtime file stays focused; the serve loops call these drain helpers at each request boundary.
//

internal import HTTP2
internal import HTTPCore
internal import HTTPTransport
internal import Synchronization

extension HTTPServer {
    /// Begins a graceful shutdown, force-closing any connection still in flight after `deadline`.
    ///
    /// Stops accepting (the transport finishes the connection stream ``run()`` consumes) and flags a
    /// drain: each in-flight connection finishes its current exchange and closes (HTTP/1 `Connection:
    /// close`, HTTP/2 GOAWAY, RFC 9113 §6.8). A connection that has not drained within `deadline` is
    /// force-closed, so a stalled peer cannot hold the process open past it. Idempotent; returns
    /// immediately when nothing is in flight.
    public func shutdown(within deadline: Duration = .seconds(10)) async {
        guard !isShuttingDown.exchange(true, ordering: .acquiringAndReleasing) else {
            return
        }
        await transport.shutdown()
        await quicTransport?.shutdown()
        let inFlight = activeConnections.withLock { Array($0.values) }
        guard !inFlight.isEmpty else {
            return  // nothing in flight — the drain is already complete
        }
        // Give in-flight connections the deadline to drain on their own, then force-close stragglers.
        try? await clock.sleep(until: clock.now.advanced(by: deadline), tolerance: nil)
        let stragglers = activeConnections.withLock { Array($0.values) }
        for connection in stragglers {
            await connection.close()
        }
    }

    /// On a draining HTTP/2 connection, queues the GOAWAY exactly once (RFC 9113 §6.8).
    func queueGoAwayIfDraining(_ engine: inout HTTP2Connection, _ sentGoAway: inout Bool) {
        guard !sentGoAway, isShuttingDown.load(ordering: .acquiring) else {
            return
        }
        engine.beginGracefulShutdown()
        sentGoAway = true
    }

    /// Whether a drained HTTP/2 connection may now close: the GOAWAY is out and no stream is in flight.
    func drainComplete(_ sentGoAway: Bool, _ engine: HTTP2Connection) -> Bool {
        sentGoAway && !engine.hasOpenStreams
    }

    /// On a draining connection, forces `Connection: close` onto an HTTP/1 response head (RFC 9110
    /// §7.6.1) and reports whether the connection is draining (so the caller closes after the exchange).
    func applyHTTP1Drain(to head: inout HTTPResponse) -> Bool {
        let draining = isShuttingDown.load(ordering: .acquiring)
        if draining {
            _ = head.headerFields.setValue("close", for: .connection)
        }
        return draining
    }
}
