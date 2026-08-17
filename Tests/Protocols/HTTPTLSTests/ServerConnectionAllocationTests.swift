//
//  ServerConnectionAllocationTests.swift
//  HTTPTLSTests
//
//  The allocation oracle at the CONNECTION level: the steady-state application-data path
//  (splitter → record layer → event) must stay at Phase 3a's shape — constant per record
//  (batch N == batch N+1, exact in release) under a per-record cap; the handshake itself may
//  allocate. Driven through the synchronous `receiveConnected` twin, because `mallocDelta`
//  measures synchronous bodies (the async `receive` has identical post-ClientHello
//  semantics; both ride the same splitter and dispatchers).
//

import Crypto
internal import HTTPTestSupport
import Testing

@testable internal import HTTPTLS

@Suite("Allocation oracle — connection steady state adds a constant per record", .serialized)
struct ServerConnectionAllocationTests {
    /// Whether this build can meet the exact contracts (the HTTPDeflate `-Onone` caveat).
    private var exact: Bool {
        #if DEBUG
            false
        #else
            true
        #endif
    }

    /// The per-record ceiling: 3a's AEAD surface cost plus the connection's event array
    /// and payload copy (both bounded, both constant).
    private static let perRecordCap = 48

    @Test("post-handshake application data is constant per record and capped")
    func steadyStateApplicationData() async throws {
        var server = TLSServerConnection(
            configuration: TLSServerConfiguration(), identity: P256TestIdentity()
        )
        var client = HandshakeTestClient()
        _ = try await server.receive(try client.helloRecord())
        try client.absorb(server.outboundBytes())
        _ = try await server.receive(try client.finishHandshake())
        #expect(server.state == .connected)
        let payload = [UInt8](repeating: 0x42, count: 2_048)
        let batch = 32
        var wire: [UInt8] = []
        for _ in 0 ..< 3 * batch {
            wire += try client.applicationDataRecord(payload)
        }
        let recordLength = wire.count / (3 * batch)
        var cursor = 0
        var delivered = 0
        func run() {
            for _ in 0 ..< batch {
                let slice = [UInt8](wire[cursor ..< cursor + recordLength])
                delivered += (try? server.receiveConnected(slice))?.count ?? 0
                cursor += recordLength
            }
        }
        run()  // warm-up: scratch growth, lazy crypto setup
        let firstDelta = mallocDelta { run() }
        let secondDelta = mallocDelta { run() }
        #expect(delivered == 3 * batch, "the measured region must actually deliver")
        guard exact, let firstDelta, let secondDelta else {
            return
        }
        #expect(
            firstDelta == secondDelta,
            "steady-state receive must not grow (\(firstDelta) vs \(secondDelta))"
        )
        #expect(
            secondDelta <= batch * Self.perRecordCap,
            "per-record cost exceeded the cap (\(secondDelta) for \(batch) records)"
        )
    }
}
