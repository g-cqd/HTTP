//
//  HTTP3SettingsTests.swift
//  HTTP3Tests
//
//  RED→GREEN driver for RFC 9114 §7.2.4 SETTINGS: parsing (Identifier, Value) varint pairs, rejecting
//  the §7.2.4.1 reserved HTTP/2 identifiers and duplicates with H3_SETTINGS_ERROR, ignoring unknown
//  identifiers, the H3_FRAME_ERROR on a truncated pair, and the encode→parse round-trip.
//

import HTTPCore
import Testing

@testable import HTTP3

@Suite("RFC 9114 §7.2.4 — HTTP/3 SETTINGS")
struct HTTP3SettingsTests {

    private func payload(_ pairs: [(UInt64, UInt64)]) -> [UInt8] {
        var out = [UInt8]()
        for (identifier, value) in pairs {
            QUICVarint.encode(identifier, into: &out)
            QUICVarint.encode(value, into: &out)
        }
        return out
    }

    private func parse(_ bytes: [UInt8]) -> (settings: HTTP3Settings?, error: HTTP3Error?) {
        bytes.withUnsafeBytes { raw -> (settings: HTTP3Settings?, error: HTTP3Error?) in
            var settings = HTTP3Settings()
            do {
                try settings.apply(raw.bytes)
                return (settings, nil)
            } catch {
                return (nil, error as? HTTP3Error)
            }
        }
    }

    @Test("parses the known HTTP/3 settings")
    func parseKnown() {
        let result = parse(payload([(0x01, 0), (0x07, 0), (0x06, 65_536), (0x08, 1)]))
        #expect(result.error == nil)
        #expect(result.settings?.qpackMaxTableCapacity == 0)
        #expect(result.settings?.qpackBlockedStreams == 0)
        #expect(result.settings?.maxFieldSectionSize == 65_536)
        #expect(result.settings?.enableConnectProtocol == true)
    }

    @Test(
        "reserved HTTP/2 setting identifiers are H3_SETTINGS_ERROR (§7.2.4.1)",
        arguments: [0x02, 0x03, 0x04, 0x05] as [UInt64])
    func reservedHTTP2Identifier(_ identifier: UInt64) {
        #expect(
            parse(payload([(identifier, 0)])).error?.code == HTTP3ErrorCode.h3SettingsError.rawValue
        )
    }

    @Test("a duplicate setting identifier is H3_SETTINGS_ERROR (§7.2.4)")
    func duplicate() {
        #expect(
            parse(payload([(0x01, 0), (0x01, 0)])).error?.code
                == HTTP3ErrorCode.h3SettingsError.rawValue)
    }

    @Test("an unknown setting identifier is ignored (§7.2.4.1)")
    func unknownIgnored() {
        let result = parse(payload([(0x4444, 99), (0x06, 4_096)]))
        #expect(result.error == nil)
        #expect(result.settings?.maxFieldSectionSize == 4_096)
    }

    @Test("ENABLE_CONNECT_PROTOCOL must be 0 or 1 (§7.2.4)")
    func connectProtocolBounds() {
        #expect(parse(payload([(0x08, 2)])).error?.code == HTTP3ErrorCode.h3SettingsError.rawValue)
    }

    @Test("a truncated (identifier, value) pair is H3_FRAME_ERROR")
    func truncatedPair() {
        // A lone identifier octet with no value following.
        #expect(parse([0x01]).error?.code == HTTP3ErrorCode.h3FrameError.rawValue)
    }

    @Test("settings round-trip through encode then parse")
    func roundTrip() {
        var original = HTTP3Settings()
        original.maxFieldSectionSize = 32_768
        let result = parse(original.encodePayload())
        #expect(result.settings == original)
    }

    @Test("the v1 default advertises QPACK capacity 0 and blocked streams 0")
    func defaultAdvertisesZero() {
        let result = parse(HTTP3Settings().encodePayload())
        #expect(result.settings?.qpackMaxTableCapacity == 0)
        #expect(result.settings?.qpackBlockedStreams == 0)
    }
}
