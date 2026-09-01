//
//  CipherSuiteMatrixTests.swift
//  HTTPTLSTests
//
//  The three RFC 8446 §B.4 suites through the same record machinery. RFC 8448 publishes
//  vectors only for TLS_AES_128_GCM_SHA256 (gated byte-exactly elsewhere); for the other two
//  the AEAD/HKDF primitives are swift-crypto's own — what THIS module adds (nonce XOR, §5.4
//  inner framing, §7.3 geometry, the ratchet) is exercised here as seal/open round-trips,
//  tamper rejection, and geometry checks across the whole matrix.
//

import Crypto
import Testing

@testable internal import HTTPTLS

@Suite("RFC 8446 §B.4 — the cipher-suite matrix round-trips")
struct CipherSuiteMatrixTests {
    private func secret(for suite: TLSCipherSuite) -> SymmetricKey {
        SymmetricKey(data: [UInt8](repeating: 0x5A, count: suite.hash.digestByteCount))
    }

    @Test("suite geometry follows §7.3/§5.5", arguments: TLSCipherSuite.allCases)
    func geometry(suite: TLSCipherSuite) {
        let keys = TLSTrafficKeys(suite: suite, trafficSecret: secret(for: suite))
        #expect(keys.key.bitCount == suite.keyLength * 8)
        #expect(keys.ivBytes.count == suite.ivLength)
        #expect(suite.ivLength == 12)
        #expect(suite.tagLength == 16)
        #expect(suite.hash.digestByteCount == (suite == .aes256GcmSha384 ? 48 : 32))
    }

    @Test(
        "seal/open round-trips across content shapes and sequences",
        arguments: TLSCipherSuite.allCases
    )
    func roundTrips(suite: TLSCipherSuite) throws {
        var sealer = TLSRecordProtector(suite: suite, trafficSecret: secret(for: suite))
        var opener = TLSRecordProtector(suite: suite, trafficSecret: secret(for: suite))
        let shapes: [[UInt8]] = [
            [],  // zero-length application data (§5.1)
            [0x42],
            [UInt8]((0 ..< 1_000).map { UInt8(truncatingIfNeeded: $0) }),
            [UInt8](repeating: 0xA5, count: TLSRecordLimits.maxPlaintextLength)  // the §5.1 cap
        ]
        for (index, shape) in shapes.enumerated() {
            var wire: [UInt8] = []
            try sealer.seal(
                type: .applicationData, fragment: shape[...], paddedLength: 64, into: &wire
            )
            let opened = try opener.open(header: wire[..<5], body: wire[5...])
            #expect(opened.type == .applicationData, "shape \(index)")
            #expect(opened.content == shape, "shape \(index)")
        }
        #expect(sealer.sequenceNumber == UInt64(shapes.count))
    }

    @Test("a flipped octet dies as the single uniform failure", arguments: TLSCipherSuite.allCases)
    func tamperRejected(suite: TLSCipherSuite) throws {
        var sealer = TLSRecordProtector(suite: suite, trafficSecret: secret(for: suite))
        var wire: [UInt8] = []
        try sealer.seal(type: .handshake, fragment: [1, 2, 3, 4][...], into: &wire)
        for index in TLSRecordLimits.headerLength ..< wire.count {
            var corrupted = wire
            corrupted[index] ^= 0x01
            var opener = TLSRecordProtector(suite: suite, trafficSecret: secret(for: suite))
            #expect(throws: TLSRecordError.badRecordMac) {
                _ = try opener.open(header: corrupted[..<5], body: corrupted[5...])
            }
        }
    }

    @Test("the §7.2 ratchet stays in sync per suite", arguments: TLSCipherSuite.allCases)
    func ratchetRoundTrips(suite: TLSCipherSuite) throws {
        var sealer = TLSRecordProtector(suite: suite, trafficSecret: secret(for: suite))
        var opener = TLSRecordProtector(suite: suite, trafficSecret: secret(for: suite))
        for generation in 0 ..< 3 {
            var wire: [UInt8] = []
            try sealer.seal(type: .applicationData, fragment: [9, 9][...], into: &wire)
            let opened = try opener.open(header: wire[..<5], body: wire[5...])
            #expect(opened.content == [9, 9], "generation \(generation)")
            sealer.ratchet()
            opener.ratchet()
        }
    }

    @Test("the record layer negotiates each suite end to end", arguments: TLSCipherSuite.allCases)
    func layerRoundTrips(suite: TLSCipherSuite) throws {
        var client = TLSRecordLayer()
        var server = TLSRecordLayer()
        _ = try server.receive([22, 3, 1, 0, 1, 1])  // a stand-in ClientHello record
        try client.installWriteKeys(suite: suite, trafficSecret: secret(for: suite))
        try server.installReadKeys(suite: suite, trafficSecret: secret(for: suite))
        try client.send(handshake: [1, 2, 3])
        let events = try server.receive(client.outboundBytes())
        #expect(events == [.handshake([1, 2, 3])])
    }
}
