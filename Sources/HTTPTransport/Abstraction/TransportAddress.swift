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

    /// Creates an address from a host and port.
    public init(host: String, port: UInt16) {
        self.host = host
        self.port = port
    }
}
