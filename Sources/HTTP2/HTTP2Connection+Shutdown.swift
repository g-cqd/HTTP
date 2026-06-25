//
//  HTTP2Connection+Shutdown.swift
//  HTTP2
//
//  RFC 9113 §6.8 — graceful connection shutdown. The server queues a GOAWAY naming the last stream it
//  will process (NO_ERROR), keeps serving the streams already in flight, and the driver closes the
//  connection once they drain. A conforming peer opens no new streams after receiving the GOAWAY.
//

extension HTTP2Connection {
    /// Queues a GOAWAY(NO_ERROR) naming the last stream this connection will process (RFC 9113 §6.8).
    ///
    /// The graceful-shutdown signal: streams already in flight continue, the peer opens no new ones,
    /// and the frame drains with the next ``outboundBytes()``. The driver sends it once, then waits on
    /// ``hasOpenStreams``.
    public mutating func beginGracefulShutdown() {
        writer.writeGoAway(lastStreamID: lastPeerStreamID, code: .noError)
    }

    /// Whether any stream is still open — a request awaiting its body, or a response still flushing.
    ///
    /// After a graceful GOAWAY the driver keeps the connection alive until this is `false`, then closes.
    public var hasOpenStreams: Bool { !streams.isEmpty }
}
