//
//  ReactorPinnedConnection.swift
//  HTTPServerTests
//
//  A ``TransportConnection`` that models a loop-backed backbone: it hands the server a serial
//  ``ReactorProbeExecutor`` as its `preferredTaskExecutor`, exactly as `POSIXKqueueConnection`,
//  `POSIXEpollConnection`, `PortableTLSConnection` and `SwiftSystemConnection` hand back their own
//  event loop — and then records, at every transport call, whether the caller was still on it
//  (audit CR-F7).
//
//  Deliberately a `final class` rather than an `actor`. An actor's methods would be isolated, and a
//  default actor in the presence of a task-executor preference borrows that preference's threads, so
//  the observation would be about the actor rather than about the caller. A nonisolated class runs
//  each call on whatever executor the caller is on, which is precisely the question these suites ask.
//

import HTTPTransport
import Synchronization

/// A connection pinned to a serial probe executor, recording where each transport call ran.
final class ReactorPinnedConnection: TransportConnection, Sendable {
    let id: TransportConnectionID
    let peer = TransportAddress(host: "reactor", port: 0)
    let negotiatedApplicationProtocol: String?
    let isSecure = false

    /// The serial "event loop" this connection prefers — the reactor under test.
    let executor: ReactorProbeExecutor

    private struct Wire {
        var inbound: ArraySlice<UInt8>
        var output: [UInt8] = []
        var receiveCount = 0
        var receivesOffReactor = 0
        var sendCount = 0
        var sendsOffReactor = 0
    }

    private let wire: Mutex<Wire>

    /// Creates a connection that will deliver `inbound` and prefer `executor`.
    init(
        id: TransportConnectionID = TransportConnectionID(1),
        inbound: [UInt8],
        alpn: String? = nil,
        executor: ReactorProbeExecutor = ReactorProbeExecutor()
    ) {
        self.id = id
        self.negotiatedApplicationProtocol = alpn
        self.executor = executor
        wire = Mutex(Wire(inbound: inbound[...]))
    }

    deinit {
        // No teardown beyond ARC; the Mutex releases with the instance.
    }

    var preferredTaskExecutor: (any TaskExecutor)? { executor }

    // MARK: TransportConnection

    func receive(maxLength: Int) async -> [UInt8]? {
        let onReactor = executor.isCurrent
        return wire.withLock { wire in
            wire.receiveCount += 1
            if !onReactor { wire.receivesOffReactor += 1 }
            guard !wire.inbound.isEmpty else {
                return nil
            }
            let count = min(maxLength, wire.inbound.count)
            defer { wire.inbound = wire.inbound.dropFirst(count) }
            return Array(wire.inbound.prefix(count))
        }
    }

    func send(_ bytes: [UInt8]) async {
        let onReactor = executor.isCurrent
        wire.withLock { wire in
            wire.sendCount += 1
            if !onReactor { wire.sendsOffReactor += 1 }
            wire.output.append(contentsOf: bytes)
        }
    }

    func close() async {
        // Nothing to release; the fake holds only in-memory buffers.
    }

    // MARK: Test inspection

    /// The bytes written to the peer so far.
    var sentBytes: [UInt8] { wire.withLock(\.output) }

    /// How many `receive` calls ran somewhere other than the connection's own reactor.
    var receivesOffReactor: Int { wire.withLock(\.receivesOffReactor) }

    /// How many `send` calls ran somewhere other than the connection's own reactor.
    var sendsOffReactor: Int { wire.withLock(\.sendsOffReactor) }

    /// Total transport calls observed, so a test can prove the counters above are not vacuously zero.
    var transportCallCount: Int { wire.withLock { $0.receiveCount + $0.sendCount } }
}
