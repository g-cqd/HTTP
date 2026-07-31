//
//  HTTP3Connection+Shutdown.swift
//  HTTP3
//
//  RFC 9114 §5.2 — graceful connection shutdown. A server announces that it will stop accepting new
//  requests by sending GOAWAY on its control stream, carrying the stream id of the first
//  client-initiated bidirectional stream it will *not* process; requests on that id or above may be
//  safely retried on a new connection. The peer may keep finishing the requests already below it.
//
//  Sent once: a later GOAWAY must not raise the boundary (§5.2), and raising it would tell a client a
//  request it had already retried elsewhere is now being processed after all.
//

internal import HTTPCore

extension HTTP3Connection {
    /// Queues our GOAWAY, announcing that no request stream at or above the named id will be processed
    /// (RFC 9114 §5.2).
    ///
    /// Idempotent — the boundary is latched on the first call, because the specification forbids a
    /// later GOAWAY from increasing it. The driver flushes it with the next ``outbound()`` drain; the
    /// action is role-addressed, so it lands on the control stream whatever id QUIC minted for it.
    public mutating func beginGracefulShutdown() {
        guard !sentGoAway else {
            return
        }
        sentGoAway = true
        // The next request stream after the highest one seen: everything below it may still complete,
        // everything from it up is refused. Client-initiated bidirectional ids step by 4 (RFC 9000
        // §2.1); with no request seen yet the boundary is 0 — nothing has been or will be processed.
        let boundary = highestRequestStreamID.map { $0.rawValue + 4 } ?? 0
        var payload: [UInt8] = []
        QUICVarint.encode(boundary, into: &payload)
        actions.append(
            .send(
                stream: .role(.control),
                bytes: HTTP3FrameWriter.frame(.goAway, payload: payload),
                fin: false
            )
        )
    }

    /// Whether any request stream is still being processed — the drain is complete when it is false.
    public var hasOpenRequestStreams: Bool {
        streams.contains { $0.value.kind == .request }
    }
}
