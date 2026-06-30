//
//  H2Wire.swift
//  HTTP2Tests
//
//  Wire-frame builders for the h2spec conformance suites (RFC 9113). h2spec drives a server by
//  feeding it crafted octets and observing the reaction; this `enum` is the encoder half of that
//  harness — every RFC 9113 §6 frame plus the preface/handshake — so each conformance test reads as
//  "build these frames, feed them, assert the engine's response". The decoder/inspector half lives in
//  `H2WireInspect.swift`. Standalone (free static builders) so the suites need no shared base type.
//

import HPACK
import HTTPCore

@testable import HTTP2

/// Builders that assemble RFC 9113 wire frames for the h2spec conformance suites.
enum H2Wire {
    // MARK: Handshake

    /// The client connection preface (RFC 9113 §3.4).
    static var clientPreface: [UInt8] { HTTP2ConnectionPreface.client }

    /// A connection advanced past the preface + SETTINGS handshake, with the server preface and
    /// SETTINGS ACK already drained — ready to be fed a crafted frame under test.
    static func handshaked(
        localSettings: HTTP2Settings = HTTP2Settings(),
        limits: HTTPLimits = .default,
        resolveBodyLimit: @escaping @Sendable (HTTPRequest) -> Int? = { _ in nil },
        clientSettings: [(id: UInt16, value: UInt32)] = []
    ) throws -> HTTP2Connection {
        var connection = HTTP2Connection(
            localSettings: localSettings, limits: limits, resolveBodyLimit: resolveBodyLimit
        )
        _ = connection.outboundBytes()  // discard the server SETTINGS preface
        var wire = clientPreface
        wire += settings(clientSettings)
        _ = try connection.receive(wire)
        _ = connection.outboundBytes()  // discard the SETTINGS ACK
        return connection
    }

    // MARK: Generic frame

    /// A complete frame: a 9-octet header (its length = `payload.count`) followed by `payload`.
    static func frame(
        _ type: HTTP2FrameType,
        flags: HTTP2FrameFlags = [],
        streamID: UInt32 = 0,
        payload: [UInt8] = []
    ) -> [UInt8] {
        var out: [UInt8] = []
        HTTP2FrameHeader(
            payloadLength: payload.count,
            type: type,
            flags: flags,
            streamID: HTTP2StreamID(streamID)
        )
        .encode(into: &out)
        out += payload
        return out
    }

    // MARK: SETTINGS (§6.5)

    /// A SETTINGS frame carrying `params` (each a 16-bit id + 32-bit value); `ack` sets the ACK flag.
    static func settings(
        _ params: [(id: UInt16, value: UInt32)] = [],
        ack: Bool = false
    ) -> [UInt8] {
        var payload: [UInt8] = []
        for parameter in params {
            payload += be16(parameter.id)
            payload += be32(parameter.value)
        }
        return frame(.settings, flags: ack ? [.ack] : [], streamID: 0, payload: payload)
    }

    // MARK: HEADERS (§6.2)

    /// HPACK-encodes `fields` into a field block fragment (a fresh encoder per call).
    static func headerBlock(_ fields: [HPACKField]) -> [UInt8] {
        var encoder = HPACKEncoder(maxDynamicTableSize: 4_096)
        return encoder.encode(fields)
    }

    /// A HEADERS frame, optionally padded (§6.2) or carrying the deprecated priority section (§5.3.2).
    ///
    /// `padding` is the pad-length octet value (that many trailing zero octets); `priority` is the
    /// (exclusive, 31-bit dependency, weight) triple.
    static func headers(
        streamID: UInt32,
        fields: [HPACKField],
        endStream: Bool = true,
        endHeaders: Bool = true,
        padding: Int? = nil,
        priority: (exclusive: Bool, dependency: UInt32, weight: UInt8)? = nil
    ) -> [UInt8] {
        var flags: HTTP2FrameFlags = []
        if endStream { flags.insert(.endStream) }
        if endHeaders { flags.insert(.endHeaders) }
        var payload: [UInt8] = []
        if let padding {
            flags.insert(.padded)
            payload.append(UInt8(padding))
        }
        if let priority {
            flags.insert(.priority)
            var dependency = be32(priority.dependency)
            if priority.exclusive { dependency[0] |= 0x80 }
            payload += dependency
            payload.append(priority.weight)
        }
        payload += headerBlock(fields)
        if let padding { payload += [UInt8](repeating: 0, count: padding) }
        return frame(.headers, flags: flags, streamID: streamID, payload: payload)
    }

    /// The four request pseudo-headers (RFC 9113 §8.3.1) plus any `extra` regular fields.
    static func requestFields(
        method: String = "GET",
        scheme: String = "https",
        authority: String? = "example.com",
        path: String = "/",
        extra: [HPACKField] = []
    ) -> [HPACKField] {
        var fields = [
            HPACKField(name: ":method", value: method),
            HPACKField(name: ":scheme", value: scheme)
        ]
        if let authority { fields.append(HPACKField(name: ":authority", value: authority)) }
        fields.append(HPACKField(name: ":path", value: path))
        fields += extra
        return fields
    }

    /// A complete GET request (HEADERS with END_STREAM + END_HEADERS).
    static func get(streamID: UInt32, path: String = "/") -> [UInt8] {
        headers(streamID: streamID, fields: requestFields(path: path), endStream: true)
    }

    /// A POST that opens a stream without END_STREAM (a body or trailers are still expected).
    static func openStream(streamID: UInt32) -> [UInt8] {
        headers(streamID: streamID, fields: requestFields(method: "POST"), endStream: false)
    }

    // MARK: DATA (§6.1)

    /// A DATA frame carrying `payload`.
    static func data(streamID: UInt32, payload: [UInt8], endStream: Bool = true) -> [UInt8] {
        frame(.data, flags: endStream ? [.endStream] : [], streamID: streamID, payload: payload)
    }

    // MARK: PRIORITY (§6.3)

    /// A PRIORITY frame: a 1-bit exclusive flag, a 31-bit dependency, and an 8-bit weight (5 octets).
    static func priority(
        streamID: UInt32,
        dependency: UInt32,
        exclusive: Bool = false,
        weight: UInt8 = 0
    ) -> [UInt8] {
        var payload = be32(dependency)
        if exclusive { payload[0] |= 0x80 }
        payload.append(weight)
        return frame(.priority, streamID: streamID, payload: payload)
    }

    // MARK: RST_STREAM (§6.4)

    /// An RST_STREAM frame carrying `code` (4 octets).
    static func rstStream(streamID: UInt32, code: HTTP2ErrorCode = .cancel) -> [UInt8] {
        frame(.rstStream, streamID: streamID, payload: be32(code.rawValue))
    }

    // MARK: PING (§6.7)

    /// A PING frame; the default payload is the 8 zero octets, `ack` sets the ACK flag.
    static func ping(
        payload: [UInt8] = [UInt8](repeating: 0, count: 8),
        ack: Bool = false
    ) -> [UInt8] {
        frame(.ping, flags: ack ? [.ack] : [], streamID: 0, payload: payload)
    }

    // MARK: WINDOW_UPDATE (§6.9)

    /// A WINDOW_UPDATE frame carrying `increment` (4 octets).
    static func windowUpdate(streamID: UInt32, increment: UInt32) -> [UInt8] {
        frame(.windowUpdate, streamID: streamID, payload: be32(increment))
    }

    // MARK: GOAWAY (§6.8)

    /// A GOAWAY frame (`onStream` is the frame's own stream id — non-zero is the §6.8 violation).
    static func goAway(
        onStream: UInt32 = 0,
        lastStreamID: UInt32 = 0,
        code: HTTP2ErrorCode = .noError
    ) -> [UInt8] {
        frame(.goAway, streamID: onStream, payload: be32(lastStreamID) + be32(code.rawValue))
    }

    // MARK: CONTINUATION (§6.10)

    /// A CONTINUATION frame carrying `fragment`.
    static func continuation(
        streamID: UInt32,
        fragment: [UInt8] = [],
        endHeaders: Bool = true
    ) -> [UInt8] {
        frame(
            .continuation,
            flags: endHeaders ? [.endHeaders] : [],
            streamID: streamID,
            payload: fragment
        )
    }

    // MARK: PUSH_PROMISE (§6.6)

    /// A PUSH_PROMISE frame — a client must never send one (RFC 9113 §8.4).
    static func pushPromise(onStream: UInt32 = 1, promisedID: UInt32 = 2) -> [UInt8] {
        frame(.pushPromise, flags: [.endHeaders], streamID: onStream, payload: be32(promisedID))
    }

    // MARK: Big-endian helpers

    private static func be16(_ value: UInt16) -> [UInt8] {
        [UInt8(value >> 8), UInt8(value & 0xFF)]
    }

    private static func be32(_ value: UInt32) -> [UInt8] {
        [
            UInt8((value >> 24) & 0xFF), UInt8((value >> 16) & 0xFF),
            UInt8((value >> 8) & 0xFF), UInt8(value & 0xFF)
        ]
    }
}
