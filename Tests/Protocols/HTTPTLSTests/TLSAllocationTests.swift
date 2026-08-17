//
//  TLSAllocationTests.swift
//  HTTPTLSTests
//
//  The allocation oracle (`mallocDelta` over the CHTTPTestMalloc counter). The engine's OWN
//  steady state is zero: every buffer (holdback, inner scratch, nonce, header) is fixed at
//  init/installation. What CANNOT be zero is swift-crypto's AEAD surface — `seal` returns its
//  ciphertext/tag as fresh `Data` and `open` returns fresh plaintext `Data`, with no
//  preallocated-output variant — so the protected paths are held to a CONSTANT per record
//  (batch N == batch N+1, exact in release: any engine-side growth breaks the equality) plus a
//  hard per-record cap. The debug `-Onone` caveat from HTTPDeflate applies: safe array writes
//  pay coroutine-frame mallocs at -Onone, so exactness is release-gated and the debug leg still
//  drives the same paths.
//

import Crypto
internal import HTTPTestSupport
import Testing

@testable internal import HTTPTLS

@Suite("Allocation oracles — engine steady state adds nothing per record", .serialized)
struct TLSAllocationTests {
    /// Whether this build can meet the exact contracts (see the file header).
    private var exact: Bool {
        #if DEBUG
            false
        #else
            true
        #endif
    }

    /// The most swift-crypto's seal/open surface is allowed to cost per record before the
    /// engine is considered to have regressed (measured ≈ a handful; generous headroom).
    private static let aeadCostCap = 32

    @Test("seal: per-record allocations are constant across batches and capped")
    func sealSteadyState() throws {
        var sealer = TLSRecordProtector(
            suite: .aes128GcmSha256,
            trafficSecret: SymmetricKey(data: RFC8448Simple.serverHandshakeTrafficSecret)
        )
        var out: [UInt8] = []
        out.reserveCapacity(1 << 16)
        let payload = [UInt8](repeating: 0x42, count: 2_048)
        let batch = 32
        func run() throws {
            for _ in 0 ..< batch {
                out.removeAll(keepingCapacity: true)
                try sealer.seal(type: .applicationData, fragment: payload[...], into: &out)
            }
        }
        try run()  // warm-up: scratch growth, lazy crypto setup
        let firstDelta = mallocDelta { try? run() }
        let secondDelta = mallocDelta { try? run() }
        #expect(sealer.sequenceNumber == UInt64(3 * batch), "the region must actually seal")
        guard exact, let firstDelta, let secondDelta else {
            return
        }
        #expect(
            firstDelta == secondDelta,
            "steady-state seal must not grow (\(firstDelta) vs \(secondDelta))"
        )
        #expect(
            secondDelta <= batch * Self.aeadCostCap,
            "per-record seal cost exceeded the cap (\(secondDelta) for \(batch) records)"
        )
    }

    @Test("open: per-record allocations are constant across batches and capped")
    func openSteadyState() throws {
        let secret = SymmetricKey(data: RFC8448Simple.serverHandshakeTrafficSecret)
        var sealer = TLSRecordProtector(suite: .aes128GcmSha256, trafficSecret: secret)
        let payload = [UInt8](repeating: 0x42, count: 2_048)
        let batch = 32
        var wire: [UInt8] = []
        for _ in 0 ..< 3 * batch {
            try sealer.seal(type: .applicationData, fragment: payload[...], into: &wire)
        }
        let recordLength = wire.count / (3 * batch)
        var opener = TLSRecordProtector(suite: .aes128GcmSha256, trafficSecret: secret)
        var cursor = 0
        var openedOctets = 0
        func run() throws {
            for _ in 0 ..< batch {
                let header = wire[cursor ..< cursor + 5]
                let body = wire[cursor + 5 ..< cursor + recordLength]
                let opened = try opener.open(header: header, body: body)
                openedOctets += opened.content.count
                cursor += recordLength
            }
        }
        try run()  // warm-up
        let firstDelta = mallocDelta { try? run() }
        let secondDelta = mallocDelta { try? run() }
        #expect(cursor == wire.count, "the measured region must consume every record")
        #expect(openedOctets == 3 * batch * payload.count)
        guard exact, let firstDelta, let secondDelta else {
            return
        }
        #expect(
            firstDelta == secondDelta,
            "steady-state open must not grow (\(firstDelta) vs \(secondDelta))"
        )
        #expect(
            secondDelta <= batch * Self.aeadCostCap,
            "per-record open cost exceeded the cap (\(secondDelta) for \(batch) records)"
        )
    }

    @Test("plaintext deframing: the holdback path allocates a constant per record")
    func plaintextReceiveSteadyState() throws {
        // Feed the same plaintext handshake record repeatedly through the layer; the events
        // and their payload copies are the ONLY per-record product (constant), and the
        // holdback/outbound machinery must add nothing that grows.
        var server = TLSRecordLayer()
        let record = RFC8448Simple.clientHelloRecord
        let batch = 32
        var seen = 0
        func run() throws {
            for _ in 0 ..< batch {
                seen += try server.receive(record).count
            }
        }
        try run()  // warm-up
        let firstDelta = mallocDelta { try? run() }
        let secondDelta = mallocDelta { try? run() }
        #expect(seen == 3 * batch, "the measured region must actually deframe")
        guard exact, let firstDelta, let secondDelta else {
            return
        }
        #expect(
            firstDelta == secondDelta,
            "steady-state deframing must not grow (\(firstDelta) vs \(secondDelta))"
        )
        #expect(
            secondDelta <= batch * 8,
            "per-record deframe cost exceeded the cap (\(secondDelta) for \(batch) records)"
        )
    }

    @Test("dropped CCS records cost zero allocations at steady state (exact in release)")
    func ccsDropAllocatesNothing() throws {
        // The one fully engine-owned receive path with no event product: a tolerated CCS is
        // parsed, validated, and dropped — nothing may allocate, and in release that is exact.
        var server = TLSRecordLayer()
        _ = try server.receive(RFC8448Simple.clientHelloRecord)
        let record = RFC8448Compat.changeCipherSpecRecord
        var seen = 0
        func run() throws {
            for _ in 0 ..< 64 {
                seen += try server.receive(record).count
            }
        }
        try run()  // warm-up
        let measured = mallocDelta { try? run() }
        #expect(seen == 0, "a tolerated CCS must surface no event")
        if exact, let measured {
            #expect(measured == 0, "a dropped CCS must not allocate (measured \(measured))")
        }
    }
}
