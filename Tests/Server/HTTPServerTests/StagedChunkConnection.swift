//
//  StagedChunkConnection.swift
//  HTTPServerTests
//
//  A transport fake that hands out one staged chunk per `receive`, so a test can reproduce a bug that
//  only manifests across MANY wire chunks (2026-07-31 audit, finding 1). `FakeConnection` delivers its
//  whole inbound array in a single read, collapsing N chunks into one wakeup, which cannot exercise a
//  per-wakeup eviction policy at all.
//

import HTTPTransport

/// A ``TransportConnection`` that hands out exactly one staged chunk per `receive`.
///
/// `FakeConnection` delivers its whole inbound array in one read, which would collapse N wire chunks
/// into a single wakeup and so could not reproduce a wakeup-eviction bug at all.
actor StagedChunkConnection: UnleasedTransportConnection {
    nonisolated let id: TransportConnectionID
    nonisolated let peer = TransportAddress(host: "staged", port: 0)
    nonisolated let negotiatedApplicationProtocol: String? = nil
    nonisolated let isSecure = false

    private var chunks: [[UInt8]]
    private var handedOut = 0
    private var sent: [UInt8] = []
    private let parksAtEnd: Bool
    private var closed = false
    private var waiter: CheckedContinuation<Void, Never>?
    private var handedOutWaiters: [(Int, CheckedContinuation<Void, Never>)] = []

    /// Stages `chunks`, handed out one per `receive`.
    ///
    /// - Parameters:
    ///   - id: the connection identity.
    ///   - chunks: the wire chunks, delivered in order.
    ///   - parksAtEnd: when true, `receive` suspends once the staged chunks run out instead of
    ///     reporting EOF, so a test can keep the session open and control exactly when it ends.
    ///     Without it the reader races ahead and its EOF ticket can overtake a broadcast wakeup.
    init(
        id: TransportConnectionID = TransportConnectionID(1),
        chunks: [[UInt8]],
        parksAtEnd: Bool = false
    ) {
        self.id = id
        self.chunks = chunks
        self.parksAtEnd = parksAtEnd
    }

    func receive(maxLength _: Int) async -> [UInt8]? {
        while handedOut >= chunks.count, parksAtEnd, !closed {
            await withCheckedContinuation { waiter = $0 }
        }
        guard handedOut < chunks.count else {
            return nil  // EOF
        }
        let chunk = chunks[handedOut]
        handedOut += 1
        wakeHandedOutWaiters()
        return chunk
    }

    func send(_ bytes: [UInt8]) async {
        sent.append(contentsOf: bytes)
    }

    func close() {
        closed = true
        handedOut = chunks.count
        waiter?.resume()
        waiter = nil
        wakeHandedOutWaiters()
    }

    /// Chunks the reader has actually pulled off the wire.
    func handedOutCount() -> Int { handedOut }

    /// Suspends until `handedOut >= threshold` (event-driven, zero `Task.yield()` spin).
    func waitForHandedOut(atLeast threshold: Int) async {
        if handedOut >= threshold {
            return
        }
        await withCheckedContinuation { continuation in
            if handedOut >= threshold {
                continuation.resume()
            }
            else {
                handedOutWaiters.append((threshold, continuation))
            }
        }
    }

    func sentBytes() -> [UInt8] { sent }

    private func wakeHandedOutWaiters() {
        guard !handedOutWaiters.isEmpty else {
            return
        }
        var remaining: [(Int, CheckedContinuation<Void, Never>)] = []
        for entry in handedOutWaiters {
            if handedOut >= entry.0 {
                entry.1.resume()
            }
            else {
                remaining.append(entry)
            }
        }
        handedOutWaiters = remaining
    }
}
