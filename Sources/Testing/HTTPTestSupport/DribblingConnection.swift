//
//  DribblingConnection.swift
//  HTTPTestSupport
//
//  A reusable fake that releases its inbound bytes a few at a time, to exercise the server's
//  incremental-read paths (parse-head-once, chunked-body-across-reads) deterministically.
//

public import HTTPTransport

/// An in-memory ``TransportConnection`` that delivers its inbound bytes `chunkSize` at a time.
public actor DribblingConnection: TransportConnection {
    /// The connection's stable identifier.
    nonisolated public let id: TransportConnectionID

    /// The peer's address.
    nonisolated public let peer: TransportAddress

    private var inbound: ArraySlice<UInt8>
    private let chunkSize: Int
    private var output: [UInt8] = []

    /// Creates a connection that releases `inbound` in `chunkSize`-byte pieces.
    public init(
        id: TransportConnectionID,
        peer: TransportAddress = TransportAddress(host: "drip", port: 0),
        inbound: [UInt8],
        chunkSize: Int
    ) {
        self.id = id
        self.peer = peer
        self.inbound = inbound[...]
        self.chunkSize = chunkSize
    }

    /// Delivers the next `chunkSize` (capped by `maxLength`) inbound bytes, or `nil` at EOF.
    public func receive(maxLength: Int) async -> [UInt8]? {
        guard !inbound.isEmpty else {
            return nil
        }
        let count = min(chunkSize, min(maxLength, inbound.count))
        defer { inbound = inbound.dropFirst(count) }
        return Array(inbound.prefix(count))
    }

    /// Records `bytes` as sent to the peer.
    public func send(_ bytes: [UInt8]) async {
        output.append(contentsOf: bytes)
    }

    /// A no-op for the in-memory connection.
    public func close() async {
        // no-op: the in-memory connection has nothing to tear down.
    }

    /// The bytes sent to the peer so far (test inspection).
    public func sentBytes() -> [UInt8] {
        output
    }
}
