//
//  WebSocketCloseCodeTests.swift
//  WebSocketTests
//
//  RFC 6455 §7.4.1 — exhaustive boundary coverage of `WebSocketCloseCode.isValidOnWire`. The valid
//  spaces are 1000–1003, 1007–1011, 3000–3999 (registered) and 4000–4999 (private); everything else —
//  including the "no code" sentinels 1004/1005/1006 and the TLS sentinel 1015 — MUST NOT appear on the
//  wire. Every range edge is asserted on both sides so a one-off in a bound, a swapped comparison, or a
//  dropped range cannot survive (see Tests/MUTATION-OPERATORS.md, operators M1/M4/M8).
//

import HTTPTestSupport
import Testing

@testable import WebSocket

@Suite("RFC 6455 §7.4.1 — Close-code wire validity (boundaries)", .tags(.mutation))
struct WebSocketCloseCodeTests {
    @Test(
        "isValidOnWire holds exactly on 1000–1003, 1007–1011, 3000–4999",
        arguments: [
            // below the first range
            (0, false), (999, false),
            // 1000–1003 application range (edges)
            (1_000, true), (1_001, true), (1_002, true), (1_003, true),
            // the gap 1004–1006 (1004 undefined, 1005/1006 "no code" sentinels)
            (1_004, false), (1_005, false), (1_006, false),
            // 1007–1011 application range (edges + interior)
            (1_007, true), (1_008, true), (1_009, true), (1_010, true), (1_011, true),
            // above 1011, incl. the 1015 TLS sentinel
            (1_012, false), (1_013, false), (1_014, false), (1_015, false), (1_016, false),
            // the reserved gap up to the registered space
            (2_000, false), (2_999, false),
            // 3000–3999 registered + 4000–4999 private (edges)
            (3_000, true), (3_999, true), (4_000, true), (4_999, true),
            // above the private space
            (5_000, false), (65_535, false)
        ] as [(UInt16, Bool)])
    func isValidOnWire(_ code: UInt16, _ expected: Bool) {
        #expect(WebSocketCloseCode(rawValue: code).isValidOnWire == expected)
    }

    @Test("the registered constants are all wire-valid (RFC 6455 §7.4.1)")
    func registeredConstantsAreValid() {
        let registered: [WebSocketCloseCode] = [
            .normalClosure, .goingAway, .protocolError, .unsupportedData,
            .invalidPayloadData, .policyViolation, .messageTooBig, .internalError
        ]
        for code in registered {
            #expect(code.isValidOnWire, "\(code.rawValue) must be wire-valid")
        }
    }

    @Test("the constants carry their RFC 6455 §7.4.1 numeric codes")
    func registeredConstantsCarryTheirCodes() {
        #expect(WebSocketCloseCode.normalClosure.rawValue == 1_000)
        #expect(WebSocketCloseCode.goingAway.rawValue == 1_001)
        #expect(WebSocketCloseCode.protocolError.rawValue == 1_002)
        #expect(WebSocketCloseCode.unsupportedData.rawValue == 1_003)
        #expect(WebSocketCloseCode.invalidPayloadData.rawValue == 1_007)
        #expect(WebSocketCloseCode.policyViolation.rawValue == 1_008)
        #expect(WebSocketCloseCode.messageTooBig.rawValue == 1_009)
        #expect(WebSocketCloseCode.internalError.rawValue == 1_011)
    }
}
