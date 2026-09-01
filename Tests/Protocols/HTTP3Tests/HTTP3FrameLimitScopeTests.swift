//
//  HTTP3FrameLimitScopeTests.swift
//  HTTP3Tests
//
//  R5-MISC — the HTTP/3 frame ceiling belongs to the frame's TYPE, not to every frame alike.
//
//  `HTTP3Connection` built its frame decoder with `maxFrameSize: limits.maxHeaderListSize`, a single
//  type-agnostic bound, so any frame whose declared Length exceeded the *header-list* ceiling was a
//  connection error (H3_EXCESSIVE_LOAD, RFC 9114 §8.1). At the defaults that rejected any DATA frame
//  over 64 KiB while `maxBodySize` was 16 MiB — a conformant peer putting a 1 MiB body in one DATA
//  frame killed the connection.
//
//  RFC 9114 does not license that. `SETTINGS_MAX_FIELD_SECTION_SIZE` (§4.2.2, §7.2.4.1) bounds a
//  *field section*, measured on the uncompressed name + value + 32 sizing; §7.2.1 defines DATA as
//  "arbitrary, variable-length sequences of bytes associated with HTTP request or response content"
//  and gives it no ceiling at all; and §7.1 defines no analogue of HTTP/2's SETTINGS_MAX_FRAME_SIZE,
//  because QUIC flow control (RFC 9000 §4) is what bounds inbound data on an HTTP/3 connection. A
//  per-frame DATA ceiling is therefore the implementation's own resource guard (CWE-770) and belongs
//  on the body budget.
//
//  NOT fixed here, and stated rather than implied: a complete DATA frame is still BUFFERED before it
//  is surfaced (`HTTP3FrameDecoder.nextFrameRange` returns nil until every payload octet has arrived).
//  Consuming DATA incrementally is a change to the frame layer's contract, not to a limit. What these
//  pin is that the buffering is bounded by the body limit rather than by the header limit.
//

import HTTPCore
import Testing

@testable import HTTP3

@Suite("RFC 9114 §7 — a frame's ceiling follows its type")
struct HTTP3FrameLimitScopeTests: HTTP3WireFixtures {
    /// A small field-section ceiling against a larger body ceiling, so the two are distinguishable.
    private static let headerCeiling = 4 * 1_024
    private static let bodyCeiling = 64 * 1_024

    private static var limits: HTTPLimits {
        HTTPLimits.default.with {
            $0.maxHeaderListSize = Self.headerCeiling
            $0.maxBodySize = Self.bodyCeiling
            // Below the body ceiling, so `max(body, webSocket)` is the body ceiling and this suite
            // measures the bound it means to measure. RFC 9220 tunnel DATA rides the WebSocket cap,
            // which is why the engine takes the larger of the two.
            $0.maxWebSocketMessageSize = 16 * 1_024
        }
    }

    private static let stream = QUICStreamID(0)

    // MARK: The engine

    @Test("a DATA frame past the field-section ceiling but inside the body ceiling is delivered")
    func dataRidesTheBodyBudget() throws {
        var connection = HTTP3Connection(limits: Self.limits)
        // 32 KiB: eight times the field-section ceiling, half the body ceiling. Legitimate content
        // that the shared ceiling refused with a CONNECTION error.
        let body = [UInt8](repeating: 0x61, count: 32 * 1_024)
        let events = try connection.receive(
            Self.stream,
            requestStream(requestFieldSection(method: "POST"), body: body),
            fin: true
        )
        guard case .request(_, _, let delivered) = events.first else {
            Issue.record("the request was not delivered: \(events)")
            return
        }
        #expect(delivered.count == body.count)
        #expect(resetStreamCode(&connection) == nil)
        #expect(closeConnectionCode(&connection) == nil)
    }

    @Test("a DATA frame past the body ceiling is still refused as excessive load")
    func dataPastTheBodyBudgetIsRefused() {
        var connection = HTTP3Connection(limits: Self.limits)
        let body = [UInt8](repeating: 0x61, count: Self.bodyCeiling + 1)
        let code = errorCode(
            feeding: &connection,
            Self.stream,
            requestStream(requestFieldSection(method: "POST"), body: body),
            fin: true
        )
        // RFC 9114 §8.1 — the guard is loosened for DATA, not removed.
        #expect(code == HTTP3ErrorCode.h3ExcessiveLoad.rawValue)
    }

    @Test("a field section past the field-section ceiling is refused, body ceiling notwithstanding")
    func headersStillRideTheFieldSectionBudget() {
        var connection = HTTP3Connection(limits: Self.limits)
        // Well inside the body ceiling and well past the field-section one: the whole point of the
        // split is that this stays refused (§4.2.2).
        let section = [UInt8](repeating: 0x00, count: Self.headerCeiling + 1)
        let code = errorCode(feeding: &connection, Self.stream, frame(.headers, section))
        #expect(code == HTTP3ErrorCode.h3ExcessiveLoad.rawValue)
    }

    @Test("a control frame past the field-section ceiling is refused")
    func controlFramesStillRideTheFieldSectionBudget() {
        var connection = HTTP3Connection(limits: Self.limits)
        // SETTINGS carries bookkeeping, not content, so a large one is abuse — it must NOT inherit
        // the loosened DATA ceiling.
        let payload = [UInt8](repeating: 0x00, count: Self.headerCeiling + 1)
        let code = errorCode(
            feeding: &connection, QUICStreamID(2), [0x00] + frame(.settings, payload)
        )
        #expect(code == HTTP3ErrorCode.h3ExcessiveLoad.rawValue)
    }

    // MARK: The decoder, driven directly

    @Test(
        "the decoder applies the DATA ceiling to DATA and the general ceiling to everything else",
        arguments: [
            (HTTP3FrameType.data, 64, true),
            (HTTP3FrameType.data, 129, false),
            (HTTP3FrameType.headers, 64, false),
            (HTTP3FrameType.settings, 64, false),
            (HTTP3FrameType.goAway, 64, false)
        ]
    )
    func perTypeCeilings(type: HTTP3FrameType, size: Int, accepted: Bool) {
        let bytes = frame(type, [UInt8](repeating: 0x41, count: size))
        let decoded: Result<HTTP3FrameDecoder.Frame?, HTTP3Error> = bytes.withUnsafeBytes { raw in
            Result { () throws(HTTP3Error) in
                var reader = ByteReader(raw)
                // A general ceiling of 32 with a DATA ceiling of 128: any size between them is
                // accepted for DATA and refused for every other type.
                return try HTTP3FrameDecoder(maxFrameSize: 32, maxDataFrameSize: 128)
                    .nextFrame(&reader)
            }
        }
        switch decoded {
            case .success(let frame):
                #expect(accepted, "\(type) of \(size) octets should have been refused")
                #expect(frame?.type == type)
            case .failure(let error):
                #expect(!accepted, "\(type) of \(size) octets should have been accepted")
                #expect(error.code == HTTP3ErrorCode.h3ExcessiveLoad.rawValue)
        }
    }

    @Test("omitting the DATA ceiling keeps one bound for every type")
    func defaultedDataCeilingMatchesTheGeneralOne() {
        let bytes = frame(.data, [UInt8](repeating: 0x41, count: 64))
        let decoded: Result<HTTP3FrameDecoder.Frame?, HTTP3Error> = bytes.withUnsafeBytes { raw in
            Result { () throws(HTTP3Error) in
                var reader = ByteReader(raw)
                return try HTTP3FrameDecoder(maxFrameSize: 32).nextFrame(&reader)
            }
        }
        guard case .failure(let error) = decoded else {
            Issue.record("a 64-octet DATA frame passed a 32-octet ceiling")
            return
        }
        #expect(error.code == HTTP3ErrorCode.h3ExcessiveLoad.rawValue)
    }
}
