//
//  QUICStreamIDTests.swift
//  HTTPCoreTests
//
//  RED→GREEN driver for the RFC 9000 §2.1 stream-identifier classification (the two low bits) and the
//  62-bit masking of the reserved high bits.
//

import Testing

@testable import HTTPCore

@Suite("QUICStreamID — RFC 9000 §2.1 classification")
struct QUICStreamIDTests {
    @Test(
        "the two low bits select initiator and directionality (RFC 9000 §2.1)",
        arguments: [
            (raw: 0, kind: QUICStreamID.Kind.clientBidirectional, client: true, uni: false),
            (raw: 1, kind: .serverBidirectional, client: false, uni: false),
            (raw: 2, kind: .clientUnidirectional, client: true, uni: true),
            (raw: 3, kind: .serverUnidirectional, client: false, uni: true),
            // The classification depends only on the low two bits, not the magnitude.
            (raw: 4, kind: .clientBidirectional, client: true, uni: false),
            (raw: 7, kind: .serverUnidirectional, client: false, uni: true)
        ] as [(raw: UInt64, kind: QUICStreamID.Kind, client: Bool, uni: Bool)])
    func classification(_ testCase: (raw: UInt64, kind: QUICStreamID.Kind, client: Bool, uni: Bool))
    {
        let id = QUICStreamID(testCase.raw)
        #expect(id.kind == testCase.kind)
        #expect(id.isClientInitiated == testCase.client)
        #expect(id.isServerInitiated == !testCase.client)
        #expect(id.isUnidirectional == testCase.uni)
        #expect(id.isBidirectional == !testCase.uni)
    }

    @Test("the reserved high bits are masked to 62 bits (RFC 9000 §2.1)")
    func masksTo62Bits() {
        // The top two bits set must be cleared; the low 62 bits survive.
        let id = QUICStreamID(rawValue: 0xFFFF_FFFF_FFFF_FFFF)
        #expect(id.rawValue == 0x3FFF_FFFF_FFFF_FFFF)
        #expect(QUICStreamID(rawValue: 0x3FFF_FFFF_FFFF_FFFF).rawValue == 0x3FFF_FFFF_FFFF_FFFF)
    }

    @Test("identifiers order and hash by their numeric value")
    func comparableAndHashable() {
        #expect(QUICStreamID(0) < QUICStreamID(4))
        #expect(QUICStreamID(4) == QUICStreamID(4))
        #expect(Set([QUICStreamID(0), QUICStreamID(0), QUICStreamID(4)]).count == 2)
    }
}
