//
//  QUICStreamDirection.swift
//  HTTPTransport
//
//  The QUIC stream abstraction for HTTP/3 (RFC 9000 §2 / RFC 9114 §6). A QUIC stream is an ordered,
//  reliable byte stream; unlike the single-stream ``TransportConnection``, the HTTP/3 engine works
//  per-stream, and it needs QUIC's end-of-stream (FIN) as a positive end-of-body signal — so
//  ``receive()`` surfaces FIN alongside the bytes. Backbones (legacy `NWConnection` / modern
//  `QUIC.Stream`) bridge their native I/O to these async methods.
//

/// Whether a QUIC stream is bidirectional or unidirectional (RFC 9000 §2.1).
public enum QUICStreamDirection: Sendable, Equatable {
    /// A bidirectional stream — an HTTP/3 request stream (RFC 9114 §6.1).
    case bidirectional
    /// A unidirectional stream — an HTTP/3 control or QPACK stream (RFC 9114 §6.2).
    case unidirectional
}
