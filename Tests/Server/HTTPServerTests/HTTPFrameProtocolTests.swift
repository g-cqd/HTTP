//
//  HTTPFrameProtocolTests.swift
//  HTTPServerTests
//
//  Phase 3.5 — the shared frame-type taxonomy and payload shape: one generic function over
//  ``HTTPFrameType`` / ``HTTPFrame`` handles both the HTTP/2 (RFC 9113) and HTTP/3 (RFC 9114) concrete
//  types, since both conform.
//

import HTTP2
import HTTP3
import HTTPCore
import Testing

@Suite("Phase 3.5 — shared HTTPFrame / HTTPFrameType")
struct HTTPFrameProtocolTests {
    /// The five core frame-type raw values, read through the ``HTTPFrameType`` protocol requirements.
    private func coreRawValues<T: HTTPFrameType>(_: T.Type) -> [Int] {
        [T.data, T.headers, T.settings, T.pushPromise, T.goAway].map { Int($0.rawValue) }
    }

    /// The payload length, read through the ``HTTPFrame`` protocol requirement.
    private func payloadLength(of frame: some HTTPFrame) -> Int {
        frame.payload.count
    }

    @Test("both versions expose the core frame taxonomy through HTTPFrameType")
    func sharedFrameTypes() {
        #expect(coreRawValues(HTTP2FrameType.self) == [0, 1, 4, 5, 7])
        #expect(coreRawValues(HTTP3FrameType.self) == [0, 1, 4, 5, 7])
    }

    @Test("a generic reader pulls the payload from either version's frame")
    func sharedFramePayload() {
        let h2 = HTTP2FrameDecoder.Frame(
            header: HTTP2FrameHeader(
                payloadLength: 3, type: .data, streamID: HTTP2StreamID(rawValue: 1)
            ),
            payload: [0x61, 0x62, 0x63]
        )
        let h3 = HTTP3FrameDecoder.Frame(type: .data, payload: [0x61, 0x62, 0x63])
        #expect(payloadLength(of: h2) == 3)
        #expect(payloadLength(of: h3) == 3)
    }
}
