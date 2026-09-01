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

    /// Always `0` — the in-memory transport binds no socket.
    public let boundPort: UInt16 = 0

    private let connections: [any TransportConnection]

    /// Creates a fake transport that will yield `connections` from ``start()``.
    public init(connections: [any TransportConnection] = []) {
        self.connections = connections
    }

    deinit {
        // No teardown beyond ARC.
    }

    /// Yields the seeded connections in order, then finishes the stream.
    ///
    /// Deliberately **ungated**: the seeded connections are built by the test, so there is no accept
    /// point at which to charge a slot and no descriptor to close on refusal. ``HTTPServer`` charges
    /// each connection it dequeues from an ungated backbone (audit F8), so the ceiling still holds —
    /// it just cannot cover the queue depth here, which a test controls anyway.
    public func start(
        admission _: ConnectionAdmission?
    ) async -> AsyncStream<any TransportConnection> {
        let connections = self.connections
        return AsyncStream { continuation in
            for connection in connections {
                continuation.yield(connection)
            }
            continuation.finish()
        }
    }

    /// Yields the seeded connections with no admission gate — the non-throwing shim.
    ///
    /// Shadows the throwing ``ServerTransport/start()`` default for the concrete fake, so a test can
    /// still write `await transport.start()` without a `try`.
    public func start() async -> AsyncStream<any TransportConnection> {
        await start(admission: nil)
    }

    /// A no-op for the in-memory transport.
    public func shutdown() async {
        // No-op: the in-memory transport holds no resources to release.
    }
}
