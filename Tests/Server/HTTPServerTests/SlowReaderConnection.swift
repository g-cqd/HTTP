//
//  SlowReaderConnection.swift
//  HTTPServerTests
//
//  A ``TransportConnection`` that models a slow / non-reading peer: it delivers one staged request, then
//  every `send` blocks until the test drains it (`drainOneSend()`) or the serve task is cancelled — in
//  which case the parked send throws `CancellationError`, exactly as a real POSIX / Network.framework
//  send does when the socket send buffer is full and the write is reaped.
//

import HTTPCore
import HTTPTestSupport
import HTTPTransport

actor SlowReaderConnection: TransportConnection {
    nonisolated let id: TransportConnectionID
    nonisolated let peer = TransportAddress(host: "slow-reader", port: 0)
    nonisolated let negotiatedApplicationProtocol: String? = nil  // cleartext HTTP/1.1 (sniffed)
    nonisolated let isSecure = false

    private var inbound: [UInt8]
    private var deliveredRequest = false
    private var sent: [UInt8] = []
    private var closed = false
    /// Each `send` parks here until the test grants one permit.
    ///
    /// One waiter at a time (the serve loop sends sequentially). Cancellation-aware,
    /// so a reaped send unblocks with `CancellationError`.
    private let sendGate = AsyncGate()

    init(request: [UInt8], id: TransportConnectionID = TransportConnectionID(1)) {
        self.id = id
        self.inbound = request
    }

    // MARK: TransportConnection

    // swiftlint:disable:next unneeded_throws_rethrows
    func receive(maxLength: Int) async throws -> [UInt8]? {
        // The peer sends exactly one request, then only reads: deliver it once, then EOF.
        guard !deliveredRequest else {
            return nil
        }
        deliveredRequest = true
        let count = min(maxLength, inbound.count)
        defer { inbound.removeFirst(count) }
        return Array(inbound.prefix(count))
    }

    func send(_ bytes: [UInt8]) async throws {
        // Block until the peer drains this write, or the reap cancels this task (throws).
        try await sendGate.waitUntilOpen()
        sent.append(contentsOf: bytes)
    }

    func close() async {
        closed = true
    }

    // MARK: Test controls

    func isClosed() -> Bool { closed }
    func sentBytes() -> [UInt8] { sent }

    /// Suspends until a `send` is parked (its write deadline is armed at that point).
    func waitForSendParked() async {
        try? await sendGate.waitForWaiters(atLeast: 1)
    }

    /// Lets the currently-parked `send` complete — the peer drained one chunk.
    func drainOneSend() {
        sendGate.open()
    }
}
