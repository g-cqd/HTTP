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

import HTTPTransport

/// A ``TransportConnection`` with test-driven inbound delivery and observable output.
actor ControllableConnection: TransportConnection {
    nonisolated let id: TransportConnectionID
    nonisolated let peer = TransportAddress(host: "controllable", port: 0)
    nonisolated let negotiatedApplicationProtocol: String?
    nonisolated let isSecure = false

    private var inbound: [UInt8] = []
    private var inboundClosed = false
    private var sent: [UInt8] = []
    private var receiveWaiter: CheckedContinuation<Void, Never>?

    init(id: TransportConnectionID = TransportConnectionID(1), alpn: String? = "h2") {
        self.id = id
        self.negotiatedApplicationProtocol = alpn
    }

    // MARK: TransportConnection

    func receive(maxLength: Int) async -> [UInt8]? {
        while inbound.isEmpty {
            if inboundClosed {
                return nil
            }
            await withCheckedContinuation { receiveWaiter = $0 }
        }
        let count = min(maxLength, inbound.count)
        defer { inbound.removeFirst(count) }
        return Array(inbound.prefix(count))
    }

    func send(_ bytes: [UInt8]) async {
        sent.append(contentsOf: bytes)
    }

    func close() {
        inboundClosed = true
        wakeReceive()
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

    private func wakeReceive() {
        receiveWaiter?.resume()
        receiveWaiter = nil
    }
}
