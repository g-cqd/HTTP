//
//  HTTP2SettingsTests.swift
//  HTTP2Tests
//
//  RED→GREEN driver for the RFC 9113 §6.5 SETTINGS frame: applying a parameter list, the §6.5.2
//  per-parameter validation, ignoring unknown identifiers, the multiple-of-6 length rule, and the
//  encode→apply round-trip.
//

import HTTPCore
import Testing

@testable import HTTP2

@Suite("RFC 9113 §6.5 — SETTINGS")
struct HTTP2SettingsTests {

    private func applied(_ bytes: [UInt8]) throws -> HTTP2Settings {
        var settings = HTTP2Settings()
        try bytes.withUnsafeBytes { try settings.apply($0.bytes) }
        return settings
    }

    private func thrownCode(_ bytes: [UInt8]) -> HTTP2ErrorCode? {
        do {
            _ = try applied(bytes)
            return nil
        } catch let error as HTTP2Error {
            return error.code
        } catch {
            return nil
        }
    }

    @Test("applies a list of known parameters (§6.5.2)")
    func appliesParameters() throws {
        let settings = try applied([
            0x00, 0x01, 0x00, 0x00, 0x20, 0x00,  // HEADER_TABLE_SIZE = 8192
            0x00, 0x03, 0x00, 0x00, 0x00, 0x64,  // MAX_CONCURRENT_STREAMS = 100
            0x00, 0x04, 0x00, 0x02, 0x00, 0x00,  // INITIAL_WINDOW_SIZE = 131072
            0x00, 0x05, 0x00, 0x00, 0x40, 0x00,  // MAX_FRAME_SIZE = 16384
        ])
        #expect(settings.headerTableSize == 8192)
        #expect(settings.maxConcurrentStreams == 100)
        #expect(settings.initialWindowSize == 131_072)
        #expect(settings.maxFrameSize == 16_384)
    }

    @Test("ignores unknown parameter identifiers (§6.5.2)")
    func ignoresUnknown() throws {
        let settings = try applied([0x00, 0x99, 0x00, 0x00, 0x00, 0x01])
        #expect(settings == HTTP2Settings())  // unchanged from defaults
    }

    @Test("a payload length not a multiple of 6 is a FRAME_SIZE_ERROR (§6.5)")
    func lengthMustBeMultipleOfSix() {
        #expect(thrownCode([0x00, 0x01, 0x00, 0x00, 0x20]) == .frameSizeError)
    }

    @Test("ENABLE_PUSH other than 0 or 1 is a PROTOCOL_ERROR (§6.5.2)")
    func enablePushMustBeBoolean() {
        #expect(thrownCode([0x00, 0x02, 0x00, 0x00, 0x00, 0x02]) == .protocolError)
    }

    @Test("INITIAL_WINDOW_SIZE above 2^31-1 is a FLOW_CONTROL_ERROR (§6.5.2)")
    func initialWindowSizeBound() {
        #expect(thrownCode([0x00, 0x04, 0x80, 0x00, 0x00, 0x00]) == .flowControlError)
    }

    @Test("MAX_FRAME_SIZE below 2^14 is a PROTOCOL_ERROR (§6.5.2)")
    func maxFrameSizeBound() {
        #expect(thrownCode([0x00, 0x05, 0x00, 0x00, 0x3F, 0xFF]) == .protocolError)  // 16383
    }

    @Test("settings round-trip through encodePayload then apply")
    func roundTrips() throws {
        var settings = HTTP2Settings()
        settings.headerTableSize = 8192
        settings.enablePush = false
        settings.maxConcurrentStreams = 250
        settings.initialWindowSize = 1 << 20
        settings.maxFrameSize = 32_768
        settings.maxHeaderListSize = 16_384
        #expect(try applied(settings.encodePayload()) == settings)
    }
}
