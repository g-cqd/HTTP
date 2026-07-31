//
//  FakeQUICStream.swift
//  HTTPServerTests
//
//  An in-memory ``QUICStream`` (RFC 9000 §2) for driving the live HTTP/3 server runtime without a
//  Network.framework QUIC handshake. Inbound chunks are scripted and released one at a time; every
//  outbound `send` and `reset` is recorded so a test can assert *which* stream the server wrote on —
//  the point of the P0.3 regression, where engine output was applied to whichever stream's task
//  happened to make the engine call.
//

import HTTPCore
import HTTPTestSupport
import HTTPTransport
import Synchronization
import Testing

/// A scripted, recording QUIC stream: a queue of inbound chunks and a log of everything sent.
final class FakeQUICStream: QUICStream, @unchecked Sendable {
    let id: QUICStreamID
    let direction: QUICStreamDirection

    private struct State {
        var inbound: [(bytes: [UInt8], fin: Bool)] = []
        var closed = false
        var sent: [(bytes: [UInt8], fin: Bool)] = []
        var resets: [UInt64] = []
        var waiter: CheckedContinuation<Void, Never>?
    }

    private let state = Mutex(State())
    /// Records this stream's id after every `receive()` that hands a chunk to the driver, so a test can
    /// sequence one stream's delivery against another's without sleeping.
    private let consumed: AsyncEventProbe<QUICStreamID>

    init(
        id: QUICStreamID,
        direction: QUICStreamDirection,
        inbound: [(bytes: [UInt8], fin: Bool)] = [],
        consumed: AsyncEventProbe<QUICStreamID> = AsyncEventProbe()
    ) {
        self.id = id
        self.direction = direction
        self.consumed = consumed
        state.withLock { $0.inbound = inbound }
    }

    deinit {
        // No teardown beyond ARC.
    }

    /// Queues another inbound chunk, waking a parked `receive()`.
    func deliver(_ bytes: [UInt8], fin: Bool) {
        let waiter = state.withLock { current -> CheckedContinuation<Void, Never>? in
            current.inbound.append((bytes, fin))
            defer { current.waiter = nil }
            return current.waiter
        }
        waiter?.resume()
    }

    /// Ends the inbound side, so a parked `receive()` returns nil (peer EOF, no FIN).
    func finishInbound() {
        let waiter = state.withLock { current -> CheckedContinuation<Void, Never>? in
            current.closed = true
            defer { current.waiter = nil }
            return current.waiter
        }
        waiter?.resume()
    }

    // swiftlint:disable:next unneeded_throws_rethrows - the QUICStream requirement is throwing
    func receive() async throws -> (bytes: [UInt8], fin: Bool)? {
        while true {
            let next = state.withLock { current -> (bytes: [UInt8], fin: Bool)?? in
                if !current.inbound.isEmpty {
                    return current.inbound.removeFirst()
                }
                return current.closed ? .some(nil) : nil
            }
            if let next {
                if next != nil {
                    consumed.record(id)
                }
                return next
            }
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                let resumeNow = state.withLock { current -> Bool in
                    guard current.inbound.isEmpty, !current.closed else {
                        return true
                    }
                    current.waiter = continuation
                    return false
                }
                if resumeNow {
                    continuation.resume()
                }
            }
        }
    }

    // swiftlint:disable:next unneeded_throws_rethrows - the QUICStream requirement is throwing
    func send(_ bytes: [UInt8], fin: Bool) async throws {
        state.withLock { $0.sent.append((bytes, fin)) }
    }

    func reset(errorCode: UInt64) {
        state.withLock { $0.resets.append(errorCode) }
    }

    /// Every octet written on this stream, concatenated in send order.
    var sentBytes: [UInt8] {
        state.withLock { $0.sent.flatMap(\.bytes) }
    }

    /// The number of `send` calls made on this stream.
    var sendCount: Int {
        state.withLock(\.sent.count)
    }

    /// The QUIC application error codes this stream was reset with (RFC 9000 §19.4).
    var resetCodes: [UInt64] {
        state.withLock(\.resets)
    }
}
