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
public import HTTPCore
internal import HTTPTransport
internal import Synchronization

extension HTTPServer {
    /// Begins a graceful shutdown: stops accepting new connections and signals every in-flight one to
    /// drain, so ``run()`` returns once they close.
    ///
    /// The transport stops accepting — finishing the connection stream ``run()`` consumes — and each
    /// in-flight connection finishes its current exchange before closing. Work that stalls is bounded
    /// by the existing idle / keep-alive timeouts. Idempotent.
    public func shutdown() async {
        guard !isShuttingDown.exchange(true, ordering: .acquiringAndReleasing) else {
            return
        }
        await transport.shutdown()
        await quicTransport?.shutdown()
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
