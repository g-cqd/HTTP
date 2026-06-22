//
//  HTTP3StreamRoleTests.swift
//  HTTP3Tests
//
//  RED→GREEN driver for the RFC 9114 §6.2 unidirectional stream-type classification: the type-byte
//  mapping (control 0x00, push 0x01, QPACK encoder 0x02, decoder 0x03), unknown types folding to
//  `reserved`, and the critical-stream classification used by H3_CLOSED_CRITICAL_STREAM.
//

import HTTPCore
import Testing

@testable import HTTP3

@Suite("RFC 9114 §6.2 — HTTP/3 stream roles")
struct HTTP3StreamRoleTests {

    @Test(
        "the §6.2 stream-type byte maps to a role",
        arguments: [
            (type: UInt64(0x00), role: HTTP3StreamRole.control),
            (type: 0x01, role: .push),
            (type: 0x02, role: .qpackEncoder),
            (type: 0x03, role: .qpackDecoder),
            (type: 0x05, role: .reserved(0x05)),
            (type: 0x21, role: .reserved(0x21)),
        ] as [(type: UInt64, role: HTTP3StreamRole)])
    func classification(_ testCase: (type: UInt64, role: HTTP3StreamRole)) {
        #expect(HTTP3StreamRole(streamType: testCase.type) == testCase.role)
        #expect(testCase.role.streamType == testCase.type)
    }

    @Test("a request stream carries no §6.2 stream-type byte")
    func requestHasNoStreamType() {
        #expect(HTTP3StreamRole.request.streamType == nil)
    }

    @Test("control and QPACK streams are critical; request/push/reserved are not (§6.2.1)")
    func critical() {
        #expect(HTTP3StreamRole.control.isCritical)
        #expect(HTTP3StreamRole.qpackEncoder.isCritical)
        #expect(HTTP3StreamRole.qpackDecoder.isCritical)
        #expect(!HTTP3StreamRole.request.isCritical)
        #expect(!HTTP3StreamRole.push.isCritical)
        #expect(!HTTP3StreamRole.reserved(0x21).isCritical)
    }
}
