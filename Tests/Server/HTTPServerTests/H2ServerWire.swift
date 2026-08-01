//
//  H2ServerWire.swift
//  HTTPServerTests
//
//  RFC 9113 frame builders and an outbound-frame reader shared by the server-side HTTP/2 suites
//  (backpressure, tunnel backpressure, stream reset). The engine-side suites have `H2Wire`, but that
//  lives in the HTTP2Tests target; these drive the *server* over a transport fake, so they need their
//  own copy of the handful of frames involved.
//
//  The reader half is what the consumption-gating suites actually assert on: how many octets the server
//  has credited back with WINDOW_UPDATE is the only externally visible measure of how much of the
//  application's backlog it has admitted (RFC 9113 §6.9).
//

import HPACK
import HTTPCore

/// RFC 9113 wire frames and outbound-frame inspection for the server-side HTTP/2 suites.
enum H2ServerWire {
    static let preface = Array("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8)

    /// The largest DATA payload these suites send — the RFC 9113 §4.2 minimum SETTINGS_MAX_FRAME_SIZE.
    static let maxFrame = 16 * 1_024

    // MARK: Builders

    static func frame(type: UInt8, flags: UInt8, streamID: UInt32, payload: [UInt8]) -> [UInt8] {
        var out: [UInt8] = [
            UInt8(payload.count >> 16 & 0xFF), UInt8(payload.count >> 8 & 0xFF),
            UInt8(payload.count & 0xFF), type, flags,
            UInt8(streamID >> 24 & 0xFF), UInt8(streamID >> 16 & 0xFF),
            UInt8(streamID >> 8 & 0xFF), UInt8(streamID & 0xFF)
        ]
        out += payload
        return out
    }

    /// An empty client SETTINGS frame (§6.5).
    static func settings() -> [UInt8] { frame(type: 0x04, flags: 0, streamID: 0, payload: []) }

    /// A HEADERS frame for `method path`, with END_HEADERS and optionally END_STREAM (§6.2).
    static func headers(
        streamID: UInt32,
        method: String = "POST",
        path: String,
        endStream: Bool = false,
        extra: [HPACKField] = []
    ) -> [UInt8] {
        var encoder = HPACKEncoder(maxDynamicTableSize: 4_096)
        let block = encoder.encode(
            [
                HPACKField(name: ":method", value: method),
                HPACKField(name: ":scheme", value: "http"),
                HPACKField(name: ":path", value: path),
                HPACKField(name: ":authority", value: "x")
            ] + extra
        )
        return frame(
            type: 0x01, flags: endStream ? 0x05 : 0x04, streamID: streamID, payload: block
        )
    }

    /// An Extended CONNECT HEADERS frame opening a WebSocket tunnel (RFC 8441 §4).
    static func extendedConnect(streamID: UInt32, path: String) -> [UInt8] {
        headers(
            streamID: streamID,
            method: "CONNECT",
            path: path,
            extra: [HPACKField(name: ":protocol", value: "websocket")]
        )
    }

    /// A DATA frame carrying `payload` (§6.1).
    static func data(streamID: UInt32, payload: [UInt8], endStream: Bool = false) -> [UInt8] {
        frame(type: 0x00, flags: endStream ? 0x01 : 0x00, streamID: streamID, payload: payload)
    }

    /// `total` filler octets split across maximum-size DATA frames (§4.2).
    static func dataFrames(streamID: UInt32, total: Int, endStream: Bool = false) -> [UInt8] {
        var wire: [UInt8] = []
        var remaining = total
        while remaining > 0 {
            let size = min(remaining, maxFrame)
            remaining -= size
            wire += data(
                streamID: streamID,
                payload: [UInt8](repeating: 0x61, count: size),
                endStream: endStream && remaining == 0
            )
        }
        return wire
    }

    /// A WINDOW_UPDATE frame granting `increment` octets on `streamID` (0 = the connection, §6.9).
    static func windowUpdate(streamID: UInt32, increment: UInt32) -> [UInt8] {
        frame(
            type: 0x08,
            flags: 0,
            streamID: streamID,
            payload: [
                UInt8(increment >> 24 & 0xFF), UInt8(increment >> 16 & 0xFF),
                UInt8(increment >> 8 & 0xFF), UInt8(increment & 0xFF)
            ]
        )
    }

    /// An RST_STREAM frame carrying `code` (§6.4).
    static func rstStream(streamID: UInt32, code: UInt32) -> [UInt8] {
        frame(
            type: 0x03,
            flags: 0,
            streamID: streamID,
            payload: [
                UInt8(code >> 24 & 0xFF), UInt8(code >> 16 & 0xFF),
                UInt8(code >> 8 & 0xFF), UInt8(code & 0xFF)
            ]
        )
    }

    // MARK: Outbound inspection

    /// One frame the server wrote: its type, flags, stream, and payload.
    struct Frame {
        let type: UInt8
        let flags: UInt8
        let streamID: UInt32
        let payload: [UInt8]
    }

    /// Every complete frame in `bytes`, in order (stops at the first incomplete tail).
    static func frames(_ bytes: [UInt8]) -> [Frame] {
        var out: [Frame] = []
        var index = 0
        while index + 9 <= bytes.count {
            let length =
                Int(bytes[index]) << 16 | Int(bytes[index + 1]) << 8 | Int(bytes[index + 2])
            let start = index + 9
            guard start + length <= bytes.count else {
                break
            }
            out.append(
                Frame(
                    type: bytes[index + 3],
                    flags: bytes[index + 4],
                    streamID: (UInt32(bytes[index + 5]) << 24 | UInt32(bytes[index + 6]) << 16
                        | UInt32(bytes[index + 7]) << 8 | UInt32(bytes[index + 8])) & 0x7FFF_FFFF,
                    payload: Array(bytes[start ..< start + length])
                )
            )
            index = start + length
        }
        return out
    }

    /// Total WINDOW_UPDATE credit the server has issued on `streamID` (0 = the connection, §6.9).
    ///
    /// The externally visible measure of how much of the peer's offered body the application has
    /// actually consumed — under consumption gating those are the same number.
    static func creditedBytes(onStream streamID: UInt32, in bytes: [UInt8]) -> Int {
        var total = 0
        for frame in frames(bytes)
        where frame.type == 0x08 && frame.streamID == streamID
            && frame.payload.count == 4
        {
            let increment =
                UInt32(frame.payload[0]) << 24 | UInt32(frame.payload[1]) << 16
                | UInt32(frame.payload[2]) << 8 | UInt32(frame.payload[3])
            total += Int(increment & 0x7FFF_FFFF)
        }
        return total
    }

    /// Whether the server began a response (HEADERS) on `streamID`.
    static func hasResponse(onStream streamID: UInt32, in bytes: [UInt8]) -> Bool {
        frames(bytes).contains { $0.type == 0x01 && $0.streamID == streamID }
    }

    /// Whether a DATA frame carrying END_STREAM has been written on `streamID`.
    static func isFinished(onStream streamID: UInt32, in bytes: [UInt8]) -> Bool {
        frames(bytes)
            .contains { $0.type == 0x00 && $0.streamID == streamID && $0.flags & 0x01 != 0 }
    }

    /// The RST_STREAM error code the server sent on `streamID`, if any (§6.4).
    static func resetCode(onStream streamID: UInt32, in bytes: [UInt8]) -> UInt32? {
        for frame in frames(bytes)
        where frame.type == 0x03 && frame.streamID == streamID && frame.payload.count == 4 {
            return UInt32(frame.payload[0]) << 24 | UInt32(frame.payload[1]) << 16
                | UInt32(frame.payload[2]) << 8 | UInt32(frame.payload[3])
        }
        return nil
    }

    /// The concatenated DATA payload the server wrote on `streamID`.
    static func body(onStream streamID: UInt32, in bytes: [UInt8]) -> [UInt8] {
        var out: [UInt8] = []
        for frame in frames(bytes) where frame.type == 0x00 && frame.streamID == streamID {
            out += frame.payload
        }
        return out
    }
}
