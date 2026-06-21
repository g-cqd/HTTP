//
//  TransportConnection.swift
//  HTTPTransport
//
//  The backbone-agnostic connection abstraction. Backbones bridge their native I/O to these async
//  methods; the HTTP engines consume the protocol and never a concrete backbone.
//

/// A stable per-connection identifier (for logging and per-client limits).
public struct TransportConnectionID: Hashable, Sendable {

    /// The underlying identifier value.
    public let rawValue: UInt64

    /// Wraps a raw identifier value.
    public init(_ rawValue: UInt64) {
        self.rawValue = rawValue
    }
}

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

/// A bidirectional byte stream to one connected peer.
///
/// Backbones bridge their native I/O — Network.framework callbacks, POSIX socket syscalls, kqueue
/// or Dispatch readiness — to these async methods. Conformers are `Sendable` and honor task
/// cancellation; bytes cross the boundary as owned buffers that the parser wraps in a `ByteReader`.
public protocol TransportConnection: Sendable {

    /// A stable identifier for this connection.
    var id: TransportConnectionID { get }

    /// The peer's address (for logging and per-client connection limits).
    var peer: TransportAddress { get }

    /// Receives up to `maxLength` inbound bytes, or `nil` once the peer half-closes (EOF).
    func receive(maxLength: Int) async throws -> [UInt8]?

    /// Sends `bytes` to the peer, completing once they are handed to the OS.
    func send(_ bytes: [UInt8]) async throws

    /// Closes the connection gracefully, flushing any pending output.
    func close() async
}
