//
//  ControllableConnection.swift
//  HTTPServerTests
//
//  A test ``TransportConnection`` whose inbound is released *on demand*, so a test can stage a late
//  WINDOW_UPDATE — feeding it only after observing that the server has streamed a partial DATA frame and
//  parked on a read. That timing is exactly what proves native HTTP/2 streaming is deadlock-free: the
//  in-memory `FakeConnection` delivers all inbound up front, which would open the window before the
//  producer ever stalls. `receive` awaits the next `feed`; `send` records output and wakes a
//  `waitUntilSent` checkpoint.
//

import HTTPTestSupport
import HTTPTransport

/// A ``TransportConnection`` with test-driven inbound delivery and observable output.
actor ControllableConnection: UnleasedTransportConnection {
    nonisolated let id: TransportConnectionID
    nonisolated let peer = TransportAddress(host: "controllable", port: 0)
    nonisolated let negotiatedApplicationProtocol: String?
    nonisolated let isSecure = false

    private var inbound: [UInt8] = []
    private var inboundClosed = false
    private var sent: [UInt8] = []
    private let receiveReady = AsyncGate()
    private var sendWaiters: [(CheckedContinuation<Void, any Error>, @Sendable ([UInt8]) -> Bool)] =
        []

    init(id: TransportConnectionID = TransportConnectionID(1), alpn: String? = "h2") {
        self.id = id
        self.negotiatedApplicationProtocol = alpn
    }

    // MARK: TransportConnection

    func receive(maxLength: Int) async throws -> [UInt8]? {
        try Task.checkCancellation()
        while inbound.isEmpty {
            if inboundClosed {
                return nil
            }
            try await receiveReady.waitUntilOpen()
        }
        let count = min(maxLength, inbound.count)
        defer { inbound.removeFirst(count) }
        return Array(inbound.prefix(count))
    }

    func send(_ bytes: [UInt8]) async {
        sent.append(contentsOf: bytes)
        wakeMatchingSendWaiters()
    }

    func close() {
        inboundClosed = true
        wakeReceive()
        let pending = sendWaiters
        sendWaiters.removeAll(keepingCapacity: true)
        for (continuation, _) in pending {
            continuation.resume(throwing: CancellationError())
        }
    }

    // MARK: Test controls

    /// Enqueues inbound bytes, waking a parked `receive`.
    func feed(_ bytes: [UInt8]) {
        inbound.append(contentsOf: bytes)
        wakeReceive()
    }

    /// Signals end-of-inbound (a later `receive` returns nil once the queue drains).
    func finishInbound() {
        inboundClosed = true
        wakeReceive()
    }

    /// All bytes the server has sent so far.
    func sentBytes() -> [UInt8] {
        sent
    }

    /// Suspends until `predicate(sentBytes)` holds (event-driven on `send`, zero `Task.yield()` spin).
    func waitUntilSent(matching predicate: @escaping @Sendable ([UInt8]) -> Bool) async throws {
        if predicate(sent) {
            return
        }
        try await withCheckedThrowingContinuation { continuation in
            if predicate(sent) {
                continuation.resume()
            }
            else if inboundClosed {
                continuation.resume(throwing: CancellationError())
            }
            else {
                sendWaiters.append((continuation, predicate))
            }
        }
    }

    private func wakeMatchingSendWaiters() {
        guard !sendWaiters.isEmpty else {
            return
        }
        var remaining: [(CheckedContinuation<Void, any Error>, @Sendable ([UInt8]) -> Bool)] = []
        for entry in sendWaiters {
            if entry.1(sent) {
                entry.0.resume()
            }
            else {
                remaining.append(entry)
            }
        }
        sendWaiters = remaining
    }

    /// Suspends until a receive is parked, so cancellation tests do not depend on scheduling.
    func waitForReceive() async throws {
        try await receiveReady.waitForWaiters(atLeast: 1)
    }

    private func wakeReceive() {
        receiveReady.open()
    }
}
