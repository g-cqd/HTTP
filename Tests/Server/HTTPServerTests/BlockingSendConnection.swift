//
//  BlockingSendConnection.swift
//  HTTPServerTests
//
//  A transport fake modelling the peer that stops reading: `send` suspends until the test releases it,
//  which stalls the HTTP/2 merged-mailbox consumer inside its flush. That is the only way to stall that
//  consumer — a blocked *handler* cannot, since handlers run as task-group children — and stalling it is
//  what exercises reader backpressure (2026-07-31 audit, finding 3).
//
//  Inbound is staged one chunk per `receive`, so the reader's pull count is directly observable.
//

import HTTPTransport

/// A ``TransportConnection`` whose `send` blocks until released, with one staged inbound chunk per read.
actor BlockingSendConnection: UnleasedTransportConnection {
    nonisolated let id: TransportConnectionID
    nonisolated let peer = TransportAddress(host: "blocking", port: 0)
    nonisolated let negotiatedApplicationProtocol: String? = "h2"
    nonisolated let isSecure = false

    private let chunks: [[UInt8]]
    private var handedOut = 0
    private var sent: [UInt8] = []
    private var sendsBlocked = true
    private var sendWaiters: [CheckedContinuation<Void, Never>] = []
    private var blockedSendObservers: [CheckedContinuation<Void, Never>] = []

    init(id: TransportConnectionID = TransportConnectionID(1), chunks: [[UInt8]]) {
        self.id = id
        self.chunks = chunks
    }

    func receive(maxLength _: Int) async -> [UInt8]? {
        guard handedOut < chunks.count else {
            return nil  // EOF
        }
        defer { handedOut += 1 }
        return chunks[handedOut]
    }

    func send(_ bytes: [UInt8]) async {
        while sendsBlocked {
            let observers = blockedSendObservers
            blockedSendObservers.removeAll()
            for observer in observers {
                observer.resume()
            }
            await withCheckedContinuation { sendWaiters.append($0) }
        }
        sent.append(contentsOf: bytes)
    }

    func close() {
        releaseSends()
    }

    // MARK: Test controls

    /// Suspends until the consumer has reached its first blocked `send`.
    func waitUntilSendBlocked() async {
        if !sendWaiters.isEmpty || !sendsBlocked {
            return
        }
        await withCheckedContinuation { blockedSendObservers.append($0) }
    }

    /// Unblocks `send`, letting the stalled consumer drain.
    func releaseSends() {
        sendsBlocked = false
        for waiter in sendWaiters {
            waiter.resume()
        }
        sendWaiters.removeAll()
        for observer in blockedSendObservers {
            observer.resume()
        }
        blockedSendObservers.removeAll()
    }

    /// Chunks the reader has actually pulled off the wire.
    func handedOutCount() -> Int { handedOut }

    /// PING ACK frames the server has written (RFC 9113 §6.7 — type 0x06 with the ACK flag).
    func pingAckCount() -> Int {
        var count = 0
        var index = 0
        while index + 9 <= sent.count {
            let length = Int(sent[index]) << 16 | Int(sent[index + 1]) << 8 | Int(sent[index + 2])
            if sent[index + 3] == 0x06, sent[index + 4] & 0x01 == 0x01 {
                count += 1
            }
            index += 9 + length
        }
        return count
    }
}
