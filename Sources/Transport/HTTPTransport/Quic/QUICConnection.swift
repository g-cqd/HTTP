//
//  QUICConnection.swift
//  HTTPTransport
//
//  The QUIC connection abstraction for HTTP/3 (RFC 9000 / RFC 9114 §3). A QUIC connection multiplexes
//  many streams: the server reads client-initiated streams from ``inboundStreams()`` and opens its own
//  (the control + QPACK unidirectional streams) with ``openStream(direction:)``. Backbones bridge the
//  legacy `NWConnectionGroup` or the modern `NetworkConnection<QUIC>` to this protocol; the HTTP/3
//  server runtime consumes only this abstraction.
//

/// One QUIC connection: a multiplexed set of streams to a single peer (RFC 9000).
public protocol QUICConnection: Sendable {
    /// The peer's network address (for logging and per-client limits).
    var peer: TransportAddress { get }

    /// The ALPN-negotiated application protocol (RFC 7301) — `"h3"` for HTTP/3 — or `nil` if unknown.
    var negotiatedApplicationProtocol: String? { get }

    /// A stream of inbound, peer-initiated QUIC streams, finishing when the connection closes.
    func inboundStreams() -> AsyncStream<any QUICStream>

    /// Opens a locally-initiated stream of the given direction (the HTTP/3 control / QPACK streams).
    func openStream(direction: QUICStreamDirection) async throws -> any QUICStream

    /// Closes the whole connection with a QUIC application error code (RFC 9000 §19.19 CONNECTION_CLOSE).
    func close(errorCode: UInt64) async
}
