//
//  H2SpecSettingsTests.swift
//  HTTP2Tests
//
//  h2spec conformance — the `http2` group, RFC 7540/9113 §6 Frame Definitions, part 2: §6.5 SETTINGS
//  (+ §6.5.2 defined parameters, §6.5.3 synchronization), §6.7 PING, §6.8 GOAWAY, and §7 Error Codes.
//  These exercise the connection-level control frames: their framing rules, parameter validation,
//  acknowledgements, and the requirement that unknown error codes trigger no special behavior.
//

import HTTPCore
import Testing

@testable import HTTP2

@Suite("h2spec http2 §6.5/6.7/6.8/7 — SETTINGS · PING · GOAWAY · Error Codes")
struct H2SpecSettingsTests {
    // MARK: §6.5 SETTINGS

    @Test("6.5/1 — a SETTINGS frame with ACK flag and a payload is a FRAME_SIZE_ERROR (§6.5)")
    func settingsAckWithPayloadIsFrameSizeError() throws {
        var connection = try H2Wire.handshaked()
        H2Wire.expectConnectionError(
            .frameSizeError,
            feeding: H2Wire.settings([(id: 0x04, value: 1)], ack: true),
            on: &connection
        )
    }

    @Test(
        "6.5/2 — a SETTINGS frame with a stream identifier other than 0x0 is a PROTOCOL_ERROR (§6.5)"
    )
    func settingsOnNonZeroStreamIsProtocolError() throws {
        var connection = try H2Wire.handshaked()
        H2Wire.expectConnectionError(
            .protocolError,
            feeding: H2Wire.frame(.settings, streamID: 1),
            on: &connection
        )
    }

    @Test(
        "6.5/3 — a SETTINGS frame whose length is not a multiple of 6 is a FRAME_SIZE_ERROR (§6.5)")
    func settingsBadLengthIsFrameSizeError() throws {
        var connection = try H2Wire.handshaked()
        H2Wire.expectConnectionError(
            .frameSizeError,
            feeding: H2Wire.frame(.settings, payload: [0x00, 0x00, 0x00]),
            on: &connection
        )
    }

    // MARK: §6.5.2 Defined SETTINGS Parameters

    @Test(
        "6.5.2 — an invalid SETTINGS parameter value is a connection error (§6.5.2)",
        arguments: [
            (
                label: "ENABLE_PUSH ≠ 0/1", id: UInt16(0x02), value: UInt32(2),
                code: HTTP2ErrorCode.protocolError
            ),
            (
                label: "INITIAL_WINDOW_SIZE > 2^31-1", id: 0x04, value: 0x8000_0000,
                code: .flowControlError
            ),
            (label: "MAX_FRAME_SIZE < 2^14", id: 0x05, value: 16_383, code: .protocolError),
            (label: "MAX_FRAME_SIZE > 2^24-1", id: 0x05, value: 16_777_216, code: .protocolError)
        ])
    func invalidSettingsValueIsConnectionError(
        _ testCase: (label: String, id: UInt16, value: UInt32, code: HTTP2ErrorCode)
    ) throws {
        var connection = try H2Wire.handshaked()
        H2Wire.expectConnectionError(
            testCase.code,
            feeding: H2Wire.settings([(id: testCase.id, value: testCase.value)]),
            on: &connection
        )
    }

    @Test("6.5.2/5 — a SETTINGS frame with an unknown identifier is ignored (§6.5.2)")
    func unknownSettingsIdentifierIsIgnored() throws {
        var connection = try H2Wire.handshaked()
        _ = try connection.receive(H2Wire.settings([(id: 0xFF, value: 1)]))
        #expect(H2Wire.hasSettingsAck(in: connection.outboundBytes()))
    }

    // MARK: §6.5.3 Settings Synchronization

    @Test("6.5.3/1 — multiple SETTINGS_INITIAL_WINDOW_SIZE values are processed in order (§6.5.3)")
    func multipleInitialWindowSizesAreProcessed() throws {
        var connection = try H2Wire.handshaked()
        // Applied as deltas in list order (the last wins); the engine must accept and acknowledge.
        _ = try connection.receive(
            H2Wire.settings([(id: 0x04, value: 100), (id: 0x04, value: 200)])
        )
        #expect(H2Wire.hasSettingsAck(in: connection.outboundBytes()))
    }

    @Test("6.5.3/2 — a SETTINGS frame without ACK is acknowledged with a SETTINGS ACK (§6.5.3)")
    func settingsWithoutAckIsAcknowledged() throws {
        var connection = try H2Wire.handshaked()
        _ = try connection.receive(H2Wire.settings())
        #expect(H2Wire.hasSettingsAck(in: connection.outboundBytes()))
    }

    // MARK: §6.7 PING

    @Test("6.7/1 — a PING frame is answered with a PING ACK carrying the identical payload (§6.7)")
    func pingIsAcknowledgedWithIdenticalPayload() throws {
        var connection = try H2Wire.handshaked()
        let payload: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 8]
        _ = try connection.receive(H2Wire.ping(payload: payload))
        #expect(H2Wire.pingAck(in: connection.outboundBytes()) == payload)
    }

    @Test("6.7/2 — a PING frame with ACK is not answered (§6.7)")
    func pingAckIsNotAnswered() throws {
        var connection = try H2Wire.handshaked()
        _ = try connection.receive(H2Wire.ping(ack: true))
        #expect(H2Wire.pingAck(in: connection.outboundBytes()) == nil)
    }

    @Test("6.7/3 — a PING frame with a stream identifier other than 0x0 is a PROTOCOL_ERROR (§6.7)")
    func pingOnNonZeroStreamIsProtocolError() throws {
        var connection = try H2Wire.handshaked()
        H2Wire.expectConnectionError(
            .protocolError,
            feeding: H2Wire.frame(.ping, streamID: 1, payload: [UInt8](repeating: 0, count: 8)),
            on: &connection
        )
    }

    @Test("6.7/4 — a PING frame with a length other than 8 is a FRAME_SIZE_ERROR (§6.7)")
    func pingWithWrongLengthIsFrameSizeError() throws {
        var connection = try H2Wire.handshaked()
        H2Wire.expectConnectionError(
            .frameSizeError,
            feeding: H2Wire.ping(payload: [UInt8](repeating: 0, count: 6)),
            on: &connection
        )
    }

    // MARK: §6.8 GOAWAY

    @Test(
        "6.8/1 — a GOAWAY frame with a stream identifier other than 0x0 is a PROTOCOL_ERROR (§6.8)")
    func goAwayOnNonZeroStreamIsProtocolError() throws {
        var connection = try H2Wire.handshaked()
        H2Wire.expectConnectionError(
            .protocolError,
            feeding: H2Wire.goAway(onStream: 1),
            on: &connection
        )
    }

    // MARK: §7 Error Codes

    @Test("7/1 — a GOAWAY frame with an unknown error code triggers no special behavior (§7)")
    func goAwayWithUnknownErrorCodeIsAccepted() throws {
        var connection = try H2Wire.handshaked()
        // last-stream-id = 0, error code = 0xFFFF (unknown). A received GOAWAY is informational.
        let wire = H2Wire.frame(.goAway, payload: [0, 0, 0, 0, 0, 0, 0xFF, 0xFF])
        H2Wire.expectAccepted(wire, on: &connection)
    }

    @Test("7/2 — an RST_STREAM frame with an unknown error code triggers no special behavior (§7)")
    func resetWithUnknownErrorCodeIsAccepted() throws {
        var connection = try H2Wire.handshaked()
        var wire = H2Wire.openStream(streamID: 1)
        wire += H2Wire.frame(.rstStream, streamID: 1, payload: [0, 0, 0xFF, 0xFF])  // unknown code
        H2Wire.expectAccepted(wire, on: &connection)
    }

    // h2spec coverage: §6.5 (3) + §6.5.2 (5) + §6.5.3 (2) + §6.7 (4) + §6.8 (1) + §7 (2) = 17 cases.
}
