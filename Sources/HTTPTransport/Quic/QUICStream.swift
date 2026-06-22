//
//  QUICStream.swift
//  HTTPTransport
//
//  The QUIC stream abstraction for HTTP/3 (RFC 9000 §2 / RFC 9114 §6). A QUIC stream is an ordered,
//  reliable byte stream; unlike the single-stream ``TransportConnection``, the HTTP/3 engine works
//  per-stream, and it needs QUIC's end-of-stream (FIN) as a positive end-of-body signal — so
//  ``receive()`` surfaces FIN alongside the bytes. Backbones (legacy `NWConnection` / modern
//  `QUIC.Stream`) bridge their native I/O to these async methods.
//

public import HTTPCore

/// Whether a QUIC stream is bidirectional or unidirectional (RFC 9000 §2.1).
public enum QUICStreamDirection: Sendable, Equatable {
    /// A bidirectional stream — an HTTP/3 request stream (RFC 9114 §6.1).
    case bidirectional
    /// A unidirectional stream — an HTTP/3 control or QPACK stream (RFC 9114 §6.2).
    case unidirectional
}

/// One QUIC stream: an ordered byte stream with an explicit end-of-stream (RFC 9000 §2).
public protocol QUICStream: Sendable {

    /// The QUIC stream identifier (RFC 9000 §2.1).
    var id: QUICStreamID { get }

    /// Whether the stream is bidirectional or unidirectional.
    var direction: QUICStreamDirection { get }

    /// Receives the next chunk of inbound bytes with QUIC's end-of-stream flag, or `nil` once the
    /// stream has been fully consumed.
    ///
    /// `fin == true` marks the peer's end-of-stream — the positive end-of-body signal the HTTP/3
    /// engine needs (RFC 9114 §4 / §7.1).
    func receive() async throws -> (bytes: [UInt8], fin: Bool)?

    /// Sends `bytes` on the stream, closing the send side with FIN when `fin` is set.
    func send(_ bytes: [UInt8], fin: Bool) async throws

    /// Abruptly resets the stream with a QUIC application error code (RFC 9000 §19.4 RESET_STREAM).
    func reset(errorCode: UInt64)
}
