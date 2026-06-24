//
//  HTTP3ErrorTests.swift
//  HTTP3Tests
//
//  RED→GREEN driver for the RFC 9114 §8.1 error-code wire values and the RFC 9114 §8 connection/stream
//  scoping, including a QPACK fault (RFC 9204 §6) surfacing as a connection error that carries the
//  QPACK code.
//

import HTTPCore
import QPACK
import Testing

@testable import HTTP3

@Suite("RFC 9114 §8 — HTTP/3 errors")
struct HTTP3ErrorTests {
    @Test(
        "the §8.1 error codes hold their wire values",
        arguments: [
            (code: HTTP3ErrorCode.h3NoError, wire: UInt64(0x0100)),
            (code: .h3ClosedCriticalStream, wire: 0x0104),
            (code: .h3FrameUnexpected, wire: 0x0105),
            (code: .h3FrameError, wire: 0x0106),
            (code: .h3ExcessiveLoad, wire: 0x0107),
            (code: .h3IdError, wire: 0x0108),
            (code: .h3SettingsError, wire: 0x0109),
            (code: .h3MissingSettings, wire: 0x010A),
            (code: .h3MessageError, wire: 0x010E),
            (code: .h3VersionFallback, wire: 0x0110)
        ] as [(code: HTTP3ErrorCode, wire: UInt64)])
    func wireValues(_ testCase: (code: HTTP3ErrorCode, wire: UInt64)) {
        #expect(testCase.code.rawValue == testCase.wire)
    }

    @Test("there are exactly 17 HTTP/3 error codes (§8.1)")
    func codeCount() {
        #expect(HTTP3ErrorCode.allCases.count == 17)
    }

    @Test("a connection error has no stream scope and carries the HTTP/3 code")
    func connectionScope() {
        let error = HTTP3Error.connection(.h3FrameUnexpected, "DATA before HEADERS")
        #expect(error.isConnectionError)
        #expect(error.streamID == nil)
        #expect(error.code == 0x0105)
    }

    @Test("a stream error carries its stream id and the HTTP/3 code")
    func streamScope() {
        let error = HTTP3Error.stream(QUICStreamID(0), .h3MessageError, "bad pseudo-header")
        #expect(!error.isConnectionError)
        #expect(error.streamID == QUICStreamID(0))
        #expect(error.code == 0x010E)
    }

    @Test("a QPACK fault surfaces as a connection error carrying the QPACK code (RFC 9204 §6)")
    func qpackFault() {
        let error = HTTP3Error.connection(qpack: .decompressionFailed, "bad field section")
        #expect(error.isConnectionError)
        #expect(error.code == 0x0200)
    }
}
