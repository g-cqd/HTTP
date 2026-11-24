//
//  SpyScatterConnection.swift
//  HTTPServerTests
//
//  Records 3-part scatter-gather `send(_:_:_:)` calls independently for issue #2 & #4 tests.
//

import HTTPTransport
import Synchronization

final class SpyScatterConnection: TransportConnection, Sendable {
    private struct State {
        var inbound: [UInt8]
        var triplets: [([UInt8], [UInt8], [UInt8])] = []
        var allSent: [UInt8] = []
        var closed = false
    }

    let id: TransportConnectionID
    let peer = TransportAddress(host: "127.0.0.1", port: 12_345)
    private let state: Mutex<State>

    init(id: TransportConnectionID, inbound: [UInt8]) {
        self.id = id
        self.state = Mutex(State(inbound: inbound))
    }

    deinit {
        // No manual resources to release.
    }

    func receive(maxLength: Int) async -> [UInt8]? {
        state.withLock { s in
            if s.inbound.isEmpty {
                return nil
            }
            let n = min(maxLength, s.inbound.count)
            let slice = Array(s.inbound.prefix(n))
            s.inbound.removeFirst(n)
            return slice
        }
    }

    func receive(into buffer: inout [UInt8], maxLength: Int) async -> Int {
        guard let chunk = await receive(maxLength: maxLength) else {
            return 0
        }
        buffer.append(contentsOf: chunk)
        return chunk.count
    }

    func send(_ bytes: [UInt8]) async {
        state.withLock { $0.allSent.append(contentsOf: bytes) }
    }

    func send(_ head: [UInt8], _ body: [UInt8], _ tail: [UInt8]) async {
        state.withLock { s in
            s.triplets.append((head, body, tail))
            s.allSent.append(contentsOf: head)
            s.allSent.append(contentsOf: body)
            s.allSent.append(contentsOf: tail)
        }
    }

    func close() async {
        state.withLock { $0.closed = true }
    }

    func sendFile(descriptor: Int32, offset: Int, length: Int) async {
        _ = (descriptor, offset, length)
    }

    func recordedTriplets() -> [([UInt8], [UInt8], [UInt8])] {
        state.withLock(\.triplets)
    }

    func allSentBytes() -> [UInt8] {
        state.withLock(\.allSent)
    }

    var isClosed: Bool {
        state.withLock(\.closed)
    }
}
