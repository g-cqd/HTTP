//
//  FakeConnection.swift
//  HTTPTransport
//
//  An in-memory connection for deterministic tests — no sockets. Lets the server/engine wiring be
//  tested without real I/O.
//

/// An in-memory ``TransportConnection`` for deterministic tests.
public actor FakeConnection: TransportConnection {
    /// The connection's stable identifier.
    nonisolated public let id: TransportConnectionID

    /// The peer's address.
    nonisolated public let peer: TransportAddress

    /// The ALPN-negotiated protocol to report (RFC 7301), injected for routing tests.
    nonisolated public let negotiatedApplicationProtocol: String?

    private var inbound: ArraySlice<UInt8>
    private var output: [UInt8] = []
    private var closed = false

    /// Creates a fake connection seeded with the `inbound` bytes the peer has "sent".
    public init(
        id: TransportConnectionID,
        peer: TransportAddress = TransportAddress(host: "fake", port: 0),
        negotiatedApplicationProtocol: String? = nil,
        inbound: [UInt8] = []
    ) {
        self.id = id
        self.peer = peer
        self.negotiatedApplicationProtocol = negotiatedApplicationProtocol
        self.inbound = inbound[...]
    }

    /// Delivers the next buffered inbound chunk (up to `maxLength`), or `nil` at EOF.
    public func receive(maxLength: Int) async -> [UInt8]? {
        guard !inbound.isEmpty else {
            return nil
        }
        let count = min(maxLength, inbound.count)
        defer { inbound = inbound.dropFirst(count) }
        return Array(inbound.prefix(count))
    }

    /// Records `bytes` as sent to the peer (throws if the connection is closed).
    public func send(_ bytes: [UInt8]) async throws {
        guard !closed else { throw TransportError.closed }
        output.append(contentsOf: bytes)
    }

    /// Marks the connection closed.
    public func close() async {
        closed = true
    }

    /// The bytes sent to the peer so far (test inspection).
    public func sentBytes() -> [UInt8] {
        output
    }
}
