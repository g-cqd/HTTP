//
//  TransportAddress.swift
//  HTTPTransport
//
//  The backbone-agnostic connection abstraction. Backbones bridge their native I/O to these async
//  methods; the HTTP engines consume the protocol and never a concrete backbone.
//

/// A peer network address.
public struct TransportAddress: Hashable, Sendable {
    /// The host (IP literal or name).
    public let host: String

    /// The port number.
    public let port: UInt16

    /// The host parsed as an IP literal, or `nil` when it is a name.
    ///
    /// Literal-only — no DNS lookup is performed, because this is read on the request path. Every
    /// socket-based backbone reports a numeric peer, so the value is normally present, and it is what
    /// a caller needs in order to mask to a prefix or key a table on the peer (see ``IPAddress``).
    public var ipAddress: IPAddress? {
        IPAddress(host)
    }

    /// Creates an address from a host and port.
    public init(host: String, port: UInt16) {
        self.host = host
        self.port = port
    }
}
