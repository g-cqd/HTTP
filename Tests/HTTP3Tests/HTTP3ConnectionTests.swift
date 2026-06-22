//
//  HTTP3ConnectionTests.swift
//  HTTP3Tests
//
//  RED→GREEN driver for the RFC 9114 connection engine's control plane: init-time SETTINGS + the
//  control/QPACK unidirectional streams, the §6.2.1 control-stream rules (SETTINGS first, no request
//  frames, critical-stream closure), the singletons (a second control/QPACK stream), GOAWAY
//  monotonicity, push refusal, the QPACK instruction-stream violations, and the Rapid Reset analog.
//

import HTTPCore
import QPACK
import Testing

@testable import HTTP3

@Suite("RFC 9114 — HTTP/3 connection (control plane)")
struct HTTP3ConnectionTests: HTTP3WireFixtures {

    private static let control = QUICStreamID(2)  // client-initiated unidirectional
    private static let qpackEncoder = QUICStreamID(6)
    private static let qpackDecoder = QUICStreamID(10)

    @Test("init queues the control + QPACK encoder/decoder streams (RFC 9114 §3.2 / §6.2)")
    func initQueuesStreams() {
        var connection = HTTP3Connection()
        let actions = connection.outbound()
        let roles = actions.compactMap { action -> HTTP3StreamRole? in
            if case .openUniStream(let role, _) = action { return role }
            return nil
        }
        #expect(roles == [.control, .qpackEncoder, .qpackDecoder])
        // The control preamble opens with the §6.2 type byte 0x00 then a SETTINGS frame.
        let controlPreamble = actions.compactMap { action -> [UInt8]? in
            if case .openUniStream(.control, let preamble) = action { return preamble }
            return nil
        }.first
        #expect(controlPreamble?.first == 0x00)
    }

    @Test("the control stream applies the peer's SETTINGS (RFC 9114 §7.2.4)")
    func appliesPeerSettings() throws {
        var connection = HTTP3Connection()
        let events = try connection.receive(
            Self.control, controlPreamble([(0x06, 8_192)]), fin: false)
        #expect(events.isEmpty)
        #expect(connection.remoteSettings.maxFieldSectionSize == 8_192)
    }

    @Test(
        "the first control-stream frame must be SETTINGS → H3_MISSING_SETTINGS (§6.2.1)")
    func firstFrameMustBeSettings() {
        var connection = HTTP3Connection()
        let bytes: [UInt8] = [0x00] + frame(.goAway, varint(0))
        #expect(
            errorCode(feeding: &connection, Self.control, bytes)
                == HTTP3ErrorCode.h3MissingSettings.rawValue)
    }

    @Test(
        "control-stream frames that are not allowed are H3_FRAME_UNEXPECTED (§7.2)",
        arguments: [
            (label: "a second SETTINGS", second: HTTP3FrameType.settings, payload: [UInt8]()),
            (label: "a DATA frame", second: .data, payload: [0x01]),
            (label: "a HEADERS frame", second: .headers, payload: [0x01]),
            (label: "a PUSH_PROMISE frame", second: .pushPromise, payload: [0x01]),
        ] as [(label: String, second: HTTP3FrameType, payload: [UInt8])])
    func unexpectedControlFrame(
        _ testCase: (label: String, second: HTTP3FrameType, payload: [UInt8])
    ) {
        var connection = HTTP3Connection()
        let bytes = controlPreamble() + frame(testCase.second, testCase.payload)
        #expect(
            errorCode(feeding: &connection, Self.control, bytes)
                == HTTP3ErrorCode.h3FrameUnexpected.rawValue)
    }

    @Test("a second control stream is H3_STREAM_CREATION_ERROR (§6.2.1)")
    func secondControlStream() throws {
        var connection = HTTP3Connection()
        _ = try connection.receive(Self.control, controlPreamble(), fin: false)
        #expect(
            errorCode(feeding: &connection, QUICStreamID(14), [0x00])
                == HTTP3ErrorCode.h3StreamCreationError.rawValue)
    }

    @Test("a closed control stream is H3_CLOSED_CRITICAL_STREAM (§6.2.1)")
    func controlStreamClosed() {
        var connection = HTTP3Connection()
        #expect(
            errorCode(feeding: &connection, Self.control, controlPreamble(), fin: true)
                == HTTP3ErrorCode.h3ClosedCriticalStream.rawValue)
    }

    @Test("a GOAWAY identifier that increases is H3_ID_ERROR (§5.2)")
    func goAwayMonotonic() throws {
        var connection = HTTP3Connection()
        let events = try connection.receive(
            Self.control, controlPreamble() + frame(.goAway, varint(8)), fin: false)
        #expect(events == [.goAway(streamID: QUICStreamID(8))])
        #expect(
            errorCode(feeding: &connection, Self.control, frame(.goAway, varint(12)))
                == HTTP3ErrorCode.h3IdError.rawValue)
    }

    @Test("a CANCEL_PUSH above MAX_PUSH_ID is H3_ID_ERROR (§7.2.3)")
    func cancelPushAboveLimit() throws {
        var connection = HTTP3Connection()
        _ = try connection.receive(Self.control, controlPreamble(), fin: false)
        // No MAX_PUSH_ID was permitted, so any push id is out of range.
        #expect(
            errorCode(feeding: &connection, Self.control, frame(.cancelPush, varint(0)))
                == HTTP3ErrorCode.h3IdError.rawValue)
    }

    @Test("a server refuses a client-initiated push stream → H3_STREAM_CREATION_ERROR (§6.2.2)")
    func refusesPushStream() {
        var connection = HTTP3Connection()
        #expect(
            errorCode(feeding: &connection, QUICStreamID(18), [0x01])
                == HTTP3ErrorCode.h3StreamCreationError.rawValue)
    }

    @Test("an unknown unidirectional stream type is tolerated (§6.2)")
    func reservedStreamTolerated() {
        var connection = HTTP3Connection()
        #expect(errorCode(feeding: &connection, QUICStreamID(22), [0x21, 0xDE, 0xAD]) == nil)
    }

    @Test(
        "a QPACK encoder Set-Capacity above the limit is QPACK_ENCODER_STREAM_ERROR (RFC 9204 §4.3.1)"
    )
    func qpackEncoderViolation() {
        var connection = HTTP3Connection()
        // [0x02] stream type (encoder); [0x25] Set Dynamic Table Capacity = 5 > 0.
        #expect(
            errorCode(feeding: &connection, Self.qpackEncoder, [0x02, 0x25])
                == UInt64(QPACKError.Code.encoderStreamError.rawValue))
    }

    @Test("a QPACK decoder Insert Count Increment is QPACK_DECODER_STREAM_ERROR (RFC 9204 §4.4.3)")
    func qpackDecoderViolation() {
        var connection = HTTP3Connection()
        // [0x03] stream type (decoder); [0x05] Insert Count Increment = 5.
        #expect(
            errorCode(feeding: &connection, Self.qpackDecoder, [0x03, 0x05])
                == UInt64(QPACKError.Code.decoderStreamError.rawValue))
    }

    @Test("a closed QPACK encoder stream is H3_CLOSED_CRITICAL_STREAM (RFC 9204 §4.2)")
    func qpackStreamClosed() {
        var connection = HTTP3Connection()
        #expect(
            errorCode(feeding: &connection, Self.qpackEncoder, [0x02], fin: true)
                == HTTP3ErrorCode.h3ClosedCriticalStream.rawValue)
    }

    @Test("a second QPACK encoder stream is H3_STREAM_CREATION_ERROR (RFC 9204 §4.2)")
    func secondQpackEncoder() throws {
        var connection = HTTP3Connection()
        _ = try connection.receive(Self.qpackEncoder, [0x02], fin: false)
        #expect(
            errorCode(feeding: &connection, QUICStreamID(14), [0x02])
                == HTTP3ErrorCode.h3StreamCreationError.rawValue)
    }

    @Test("a reserved HTTP/2 setting identifier is H3_SETTINGS_ERROR (§7.2.4.1)")
    func reservedSettingIdentifier() {
        var connection = HTTP3Connection()
        let bytes: [UInt8] = [0x00] + frame(.settings, settingsPayload([(0x02, 1)]))
        #expect(
            errorCode(feeding: &connection, Self.control, bytes)
                == HTTP3ErrorCode.h3SettingsError.rawValue)
    }

    @Test("excessive stream resets trip H3_EXCESSIVE_LOAD (the Rapid Reset analog, §8.1)")
    func rapidReset() {
        var limits = HTTPLimits()
        limits.maxStreamResetsPerInterval = 2
        var connection = HTTP3Connection(limits: limits)
        _ = connection.outbound()  // drain the init actions
        for raw: UInt64 in [0, 4, 8] {  // three client-initiated bidirectional request streams
            connection.registerStream(QUICStreamID(raw), direction: .bidirectional)
            _ = connection.resetStream(QUICStreamID(raw), errorCode: 0x010C)
        }
        #expect(closeConnectionCode(&connection) == HTTP3ErrorCode.h3ExcessiveLoad.rawValue)
    }
}
