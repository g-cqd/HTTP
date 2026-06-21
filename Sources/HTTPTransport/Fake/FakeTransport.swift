//
//  FakeTransport.swift
//  HTTPTransport
//
//  An in-memory server transport that yields a fixed set of connections — for deterministic tests.
//

/// An in-memory ``ServerTransport`` that yields a fixed set of connections (no sockets).
public final class FakeTransport: ServerTransport {

    /// The backbone identity (``TransportBackbone/fake``).
    public let backbone: TransportBackbone = .fake

    private let connections: [any TransportConnection]

    /// Creates a fake transport that will yield `connections` from ``start()``.
    public init(connections: [any TransportConnection] = []) {
        self.connections = connections
    }

    /// Yields the seeded connections in order, then finishes the stream.
    public func start() async throws -> AsyncStream<any TransportConnection> {
        let connections = self.connections
        return AsyncStream { continuation in
            for connection in connections {
                continuation.yield(connection)
            }
            continuation.finish()
        }
    }

    /// A no-op for the in-memory transport.
    public func shutdown() async {}
}
