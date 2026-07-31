//
//  DispatchPlanWire.swift
//  HTTPServerTests
//
//  Wire construction and decoding shared by the dispatch-plan suites (audit CR-F12 / CR-F19), which
//  have to drive the *same* request over all three protocols to compare what each costs.
//

import HPACK
import HTTP2
import HTTPCore
import QPACK
import Testing

/// HTTP/2 and HTTP/3 request wire for a POST with a separately delivered body.
enum DispatchPlanWire {
    // MARK: HTTP/2

    /// The client preface, SETTINGS, and a HEADERS frame for `POST path` without END_STREAM.
    static func http2Head(path: String, streamID: UInt32 = 1) -> [UInt8] {
        H2ServerWire.preface + H2ServerWire.settings()
            + H2ServerWire.headers(streamID: streamID, method: "POST", path: path)
    }

    /// A DATA frame of `count` filler octets carrying END_STREAM.
    static func http2Body(count: Int, streamID: UInt32 = 1) -> [UInt8] {
        H2ServerWire.frame(
            type: 0x00,
            flags: 0x01,
            streamID: streamID,
            payload: Array(repeating: UInt8(ascii: "x"), count: count)
        )
    }

    /// The `:status` and concatenated DATA payloads of an HTTP/2 response.
    static func decodeHTTP2(_ bytes: [UInt8]) throws -> (status: String?, body: [UInt8]) {
        var decoder = HPACKDecoder(maxDynamicTableSize: 4_096)
        var status: String?
        var body: [UInt8] = []
        try bytes.withUnsafeBytes { raw in
            var reader = ByteReader(raw)
            let frames = HTTP2FrameDecoder()
            while let frame = try frames.nextFrame(&reader) {
                switch frame.header.type {
                    case .headers:
                        let fragment = try HTTP2HeadersFrame.fieldBlockFragment(
                            frame.payload, flags: frame.header.flags
                        )
                        let fields = try Array(fragment)
                            .withUnsafeBytes { try decoder.decode($0.bytes) }
                        for field in fields where field.name == ":status" { status = field.value }
                    case .data:
                        body.append(contentsOf: frame.payload)
                    default:
                        break
                }
            }
        }
        return (status, body)
    }

    // MARK: HTTP/3

    /// A HEADERS frame (RFC 9114 §7.2.2) for `POST path`, QPACK-encoded statically.
    static func http3Head(path: String, contentLength: Int? = nil) -> [UInt8] {
        var fields = [
            HeaderField(name: ":method", value: "POST"),
            HeaderField(name: ":scheme", value: "https"),
            HeaderField(name: ":authority", value: "example.com"),
            HeaderField(name: ":path", value: path)
        ]
        if let contentLength {
            fields.append(HeaderField(name: "content-length", value: String(contentLength)))
        }
        return frame(type: 0x01, payload: QPACKEncoder().encode(fields))
    }

    /// A DATA frame (RFC 9114 §7.2.1) of `count` filler octets.
    static func http3Body(count: Int) -> [UInt8] {
        frame(type: 0x00, payload: Array(repeating: UInt8(ascii: "x"), count: count))
    }

    /// The `:status` and concatenated DATA payloads of an HTTP/3 response.
    static func decodeHTTP3(_ bytes: [UInt8]) throws -> (status: String?, body: [UInt8]) {
        var status: String?
        var body: [UInt8] = []
        var index = 0
        while index < bytes.count {
            guard let next = nextFrame(Array(bytes[index...])) else {
                break
            }
            index += next.consumed
            switch next.type {
                case 0x01:
                    let fields = try next.payload
                        .withUnsafeBytes { try QPACKDecoder().decode($0.bytes) }
                    for field in fields where field.name == ":status" { status = field.value }
                case 0x00:
                    body.append(contentsOf: next.payload)
                default:
                    break
            }
        }
        return (status, body)
    }

    private static func frame(type: UInt64, payload: [UInt8]) -> [UInt8] {
        var out: [UInt8] = []
        QUICVarint.encode(type, into: &out)
        QUICVarint.encode(UInt64(payload.count), into: &out)
        out.append(contentsOf: payload)
        return out
    }

    private static func nextFrame(
        _ bytes: [UInt8]
    ) -> (type: UInt64, payload: [UInt8], consumed: Int)? {
        bytes.withUnsafeBytes { raw -> (type: UInt64, payload: [UInt8], consumed: Int)? in
            var reader = ByteReader(raw)
            guard let type = QUICVarint.decode(&reader),
                let length = QUICVarint.decode(&reader),
                reader.position + Int(length) <= bytes.count
            else {
                return nil
            }
            let start = reader.position
            return (type, Array(bytes[start ..< (start + Int(length))]), start + Int(length))
        }
    }

    /// Polls `condition` until it holds, failing the test if the budget runs out.
    ///
    /// The budget exhausting is a *failure*, not a quiet return. Falling out of the loop with the
    /// condition still false let the test carry on and either pass vacuously or fail later at a
    /// confusing assertion — which is how a genuinely unmet condition could read as a green run.
    static func settle(until condition: @Sendable () -> Bool) async throws {
        for _ in 0 ..< 300 where !condition() {
            try await Task.sleep(for: .milliseconds(10))
        }
        #expect(condition(), "settle budget exhausted with the condition still false")
    }

    /// Polls an `async` `condition` until it holds, failing the test if the budget runs out.
    ///
    /// See ``settle(until:)`` — exhausting the budget is a failure, not a quiet return.
    static func settleAsync(until condition: @Sendable () async -> Bool) async throws {
        for _ in 0 ..< 300 where await !condition() {
            try await Task.sleep(for: .milliseconds(10))
        }
        #expect(await condition(), "settle budget exhausted with the condition still false")
    }
}
