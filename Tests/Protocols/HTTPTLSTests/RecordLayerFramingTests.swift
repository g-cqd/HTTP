//
//  RecordLayerFramingTests.swift
//  HTTPTLSTests
//
//  RFC 8446 §5 framing edges beyond the RFC 8448 traces: the 2^14 fragmentation cap and its
//  reassembly, every length-cap rejection (checked from the header alone — before body octets
//  are even awaited), the §5.4 padding policy round-trip, the §5.1/§6 shape rules (zero-length
//  handshake, one alert per record, CCS body exactness), the §7.1 key-ladder misuse cases, and
//  the §5.5 limit behavior (never wrap; needsKeyUpdate margin; §7.2 ratchet round-trip).
//

import Crypto
import Testing

@testable internal import HTTPTLS

@Suite("RFC 8446 §5 — record framing edges")
struct RecordLayerFramingTests {
    private let clientHs = SymmetricKey(data: RFC8448Simple.clientHandshakeTrafficSecret)

    /// A server layer that has consumed the §3 ClientHello (opens the CCS window etc.).
    private func serverAfterClientHello() throws -> TLSRecordLayer {
        var server = TLSRecordLayer()
        _ = try server.receive(RFC8448Simple.clientHelloRecord)
        return server
    }

    // MARK: Fragmentation and reassembly (§5.1)

    @Test("outbound handshake content fragments at 2^14 and reassembles losslessly")
    func fragmentationRoundTrips() throws {
        var sender = TLSRecordLayer()
        let content = [UInt8]((0 ..< 40_000).map { UInt8(truncatingIfNeeded: $0) })
        try sender.send(handshake: content)
        let wire = sender.outboundBytes()
        // 40 000 octets → 16384 + 16384 + 7232, each in its own §5.1 record.
        #expect(wire.count == content.count + 3 * TLSRecordLimits.headerLength)
        var receiver = TLSRecordLayer()
        let events = try receiver.receive(wire)
        var reassembled: [UInt8] = []
        for event in events {
            guard case .handshake(let fragment) = event else {
                Issue.record("unexpected event \(event)")
                return
            }
            reassembled += fragment
        }
        #expect(events.count == 3)
        #expect(reassembled == content)
    }

    @Test("the §5.4 padding policy pads sealed records and strips transparently")
    func paddingRoundTrips() throws {
        var sender = TLSRecordLayer()
        try sender.installWriteKeys(suite: .aes128GcmSha256, trafficSecret: clientHs)
        sender.paddingGranularity = 256
        try sender.send(handshake: [1, 2, 3])
        let wire = sender.outboundBytes()
        // inner = 3 content + 1 type, padded to 256, plus tag and header.
        #expect(wire.count == TLSRecordLimits.headerLength + 256 + 16)
        var receiver = try serverAfterClientHello()
        try receiver.installReadKeys(suite: .aes128GcmSha256, trafficSecret: clientHs)
        #expect(try receiver.receive(wire) == [.handshake([1, 2, 3])])
    }

    // MARK: Length caps, checked before payloads arrive (§5.1/§5.2)

    @Test(
        "length caps reject from the header alone",
        arguments: [
            (UInt8(22), 16_385),  // plaintext > 2^14 (§5.1)
            (UInt8(23), 16_641),  // ciphertext > 2^14 + 256 (§5.2)
            (UInt8(21), 16_385)  // alert record over the plaintext cap (§5.1)
        ]
    )
    func lengthLiesRejectEarly(type: UInt8, length: Int) throws {
        var server = try serverAfterClientHello()
        let header: [UInt8] = [
            type, 3, 3, UInt8(truncatingIfNeeded: length >> 8), UInt8(truncatingIfNeeded: length)
        ]
        // ONLY the header is fed — the overflow must be caught with zero body octets buffered.
        #expect(throws: TLSRecordError.recordOverflow) {
            _ = try server.receive(header)
        }
    }

    @Test("an unknown outer content type is fatal (§5)")
    func unknownOuterTypeRejected() throws {
        var server = try serverAfterClientHello()
        #expect(throws: TLSRecordError.unknownContentType(0x42)) {
            _ = try server.receive([0x42, 3, 3, 0, 1, 0])
        }
    }

    @Test("the legacy version octets are ignored for all purposes (§5.1)")
    func legacyVersionIgnored() throws {
        var mangled = RFC8448Simple.clientHelloRecord
        mangled[1] = 0x7F
        mangled[2] = 0x99
        var server = TLSRecordLayer()
        #expect(try server.receive(mangled) == [.handshake(RFC8448Simple.clientHello)])
    }

    // MARK: Shape rules (§5.1 handshake, §6 alerts, §5/D.4 CCS)

    @Test("a zero-length handshake record is fatal (§5.1)")
    func emptyHandshakeRejected() throws {
        var server = try serverAfterClientHello()
        #expect(throws: TLSRecordError.emptyHandshakeRecord) {
            _ = try server.receive([22, 3, 3, 0, 0])
        }
    }

    @Test(
        "an alert record must be exactly one 2-octet alert (§6)",
        arguments: [[UInt8](), [1], [1, 0, 1]]
    )
    func malformedAlertRejected(body: [UInt8]) throws {
        var server = try serverAfterClientHello()
        let record = [21, 3, 3, 0, UInt8(truncatingIfNeeded: body.count)] + body
        #expect(throws: TLSRecordError.malformedAlertRecord) {
            _ = try server.receive(record)
        }
    }

    @Test("application data without keys to open it is fatal (§5.2)")
    func plaintextApplicationDataRejected() throws {
        var server = try serverAfterClientHello()
        #expect(throws: TLSRecordError.unexpectedPlaintextRecord(.applicationData)) {
            _ = try server.receive([23, 3, 3, 0, 1, 0])
        }
    }

    @Test("unprotected handshake and alert records are fatal once read keys rule (§5.2/§6)")
    func plaintextAfterKeysRejected() throws {
        var server = try serverAfterClientHello()
        try server.installReadKeys(suite: .aes128GcmSha256, trafficSecret: clientHs)
        #expect(throws: TLSRecordError.unexpectedPlaintextRecord(.handshake)) {
            _ = try server.receive([22, 3, 3, 0, 1, 0])
        }
        var server2 = try serverAfterClientHello()
        try server2.installReadKeys(suite: .aes128GcmSha256, trafficSecret: clientHs)
        #expect(throws: TLSRecordError.unexpectedPlaintextRecord(.alert)) {
            _ = try server2.receive([21, 3, 3, 0, 2, 1, 0])
        }
    }

    @Test(
        "a CCS whose body is not exactly 0x01 is fatal (§5)",
        arguments: [[UInt8](), [2], [1, 1]]
    )
    func malformedCCSRejected(body: [UInt8]) throws {
        var server = try serverAfterClientHello()
        let record = [20, 3, 3, 0, UInt8(truncatingIfNeeded: body.count)] + body
        #expect(throws: TLSRecordError.unexpectedChangeCipherSpec) {
            _ = try server.receive(record)
        }
    }

    @Test("sendChangeCipherSpec writes the D.4 record and refuses after write keys")
    func sendCCS() throws {
        var server = TLSRecordLayer()
        try server.sendChangeCipherSpec()
        #expect(server.outboundBytes() == RFC8448Compat.changeCipherSpecRecord)
        try server.installWriteKeys(suite: .aes128GcmSha256, trafficSecret: clientHs)
        #expect(throws: TLSRecordError.invalidKeyInstallation) {
            try server.sendChangeCipherSpec()
        }
    }

    // MARK: The §5.4 inner-plaintext rejections (crafted with the real keys)

    /// Seals a raw inner plaintext under the client handshake keys, seq 0 (bypassing the seal
    /// path's own §5.4 assembly so degenerate inners can be crafted).
    private func craftRecord(inner: [UInt8]) throws -> [UInt8] {
        let keys = TLSTrafficKeys(suite: .aes128GcmSha256, trafficSecret: clientHs)
        let bodyLength = inner.count + 16
        let header: [UInt8] = [
            23, 3, 3, UInt8(truncatingIfNeeded: bodyLength >> 8),
            UInt8(truncatingIfNeeded: bodyLength)
        ]
        let box = try AES.GCM.seal(
            inner,
            using: keys.key,
            nonce: AES.GCM.Nonce(data: keys.ivBytes),
            authenticating: header
        )
        return header + box.ciphertext + box.tag
    }

    @Test("an all-padding inner plaintext (no content type) is fatal (§5.4)")
    func allPaddingRejected() throws {
        var server = try serverAfterClientHello()
        try server.installReadKeys(suite: .aes128GcmSha256, trafficSecret: clientHs)
        let record = try craftRecord(inner: [UInt8](repeating: 0, count: 32))
        #expect(throws: TLSRecordError.missingContentType) {
            _ = try server.receive(record)
        }
    }

    @Test("an unknown inner content type is fatal (§5.2)")
    func unknownInnerTypeRejected() throws {
        var server = try serverAfterClientHello()
        try server.installReadKeys(suite: .aes128GcmSha256, trafficSecret: clientHs)
        let record = try craftRecord(inner: [1, 2, 3, 0x42])
        #expect(throws: TLSRecordError.unknownContentType(0x42)) {
            _ = try server.receive(record)
        }
    }

    @Test("an encrypted CCS is fatal — CCS is never protected (§5)")
    func protectedCCSRejected() throws {
        var server = try serverAfterClientHello()
        try server.installReadKeys(suite: .aes128GcmSha256, trafficSecret: clientHs)
        let record = try craftRecord(inner: [1, 20])
        #expect(throws: TLSRecordError.unexpectedProtectedRecord(.changeCipherSpec)) {
            _ = try server.receive(record)
        }
    }

    @Test("inner application data under handshake read keys is fatal (§7.1)")
    func earlyApplicationDataRejected() throws {
        var server = try serverAfterClientHello()
        try server.installReadKeys(suite: .aes128GcmSha256, trafficSecret: clientHs)
        let record = try craftRecord(inner: [9, 9, 9, 23])
        #expect(throws: TLSRecordError.unexpectedProtectedRecord(.applicationData)) {
            _ = try server.receive(record)
        }
    }

    // MARK: Key-ladder misuse (§7.1)

    @Test("the key ladder refuses to climb past application or switch suites")
    func ladderMisuseRejected() throws {
        var server = TLSRecordLayer()
        try server.installReadKeys(suite: .aes128GcmSha256, trafficSecret: clientHs)
        #expect(throws: TLSRecordError.invalidKeyInstallation) {
            try server.installReadKeys(suite: .chaCha20Poly1305Sha256, trafficSecret: clientHs)
        }
        try server.installReadKeys(suite: .aes128GcmSha256, trafficSecret: clientHs)
        #expect(throws: TLSRecordError.invalidKeyInstallation) {
            try server.installReadKeys(suite: .aes128GcmSha256, trafficSecret: clientHs)
        }
    }

    @Test("ratchets exist only at the application epoch; app data needs app write keys")
    func ratchetAndSendMisuseRejected() throws {
        var server = TLSRecordLayer()
        #expect(throws: TLSRecordError.invalidKeyInstallation) {
            try server.ratchetWriteKeys()
        }
        try server.installWriteKeys(suite: .aes128GcmSha256, trafficSecret: clientHs)
        #expect(throws: TLSRecordError.invalidKeyInstallation) {
            try server.ratchetWriteKeys()
        }
        #expect(throws: TLSRecordError.invalidKeyInstallation) {
            try server.send(applicationData: [1])
        }
    }

    // MARK: §5.5 limits and the §7.2 ratchet

    @Test("sealing refuses at the §5.5 bound and signals KeyUpdate inside the margin")
    func recordLimitNeverWraps() throws {
        var protector = TLSRecordProtector(suite: .aes128GcmSha256, trafficSecret: clientHs)
        #expect(!protector.needsKeyUpdate)
        protector.sequenceNumber = TLSCipherSuite.aes128GcmSha256.protectionSoftLimit - 65_536
        #expect(protector.needsKeyUpdate)
        protector.sequenceNumber = TLSCipherSuite.aes128GcmSha256.protectionSoftLimit
        var out: [UInt8] = []
        #expect(throws: TLSRecordError.recordLimitReached) {
            try protector.seal(type: .applicationData, fragment: [1][...], into: &out)
        }
        #expect(out.isEmpty)
    }

    @Test("the §7.2 ratchet round-trips, resets the sequence, and retires the old keys")
    func ratchetRoundTrips() throws {
        var sealer = TLSRecordProtector(suite: .aes128GcmSha256, trafficSecret: clientHs)
        var opener = TLSRecordProtector(suite: .aes128GcmSha256, trafficSecret: clientHs)
        var old: [UInt8] = []
        try sealer.seal(type: .applicationData, fragment: [1, 2][...], into: &old)
        sealer.ratchet()
        opener.ratchet()
        #expect(sealer.sequenceNumber == 0)
        #expect(sealer.generation == 1)
        var wire: [UInt8] = []
        try sealer.seal(type: .applicationData, fragment: [3, 4][...], into: &wire)
        let opened = try opener.open(header: wire[..<5], body: wire[5...])
        #expect(opened.content == [3, 4])
        // The pre-ratchet record is now under retired keys — uniform failure.
        var lateOpener = opener
        #expect(throws: TLSRecordError.badRecordMac) {
            _ = try lateOpener.open(header: old[..<5], body: old[5...])
        }
    }
}
