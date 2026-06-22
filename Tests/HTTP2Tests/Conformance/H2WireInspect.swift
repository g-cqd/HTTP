//
//  H2WireInspect.swift
//  HTTP2Tests
//
//  The decoder/assertion half of the h2spec harness (RFC 9113). h2spec judges a server by what it
//  writes back, so these helpers decode the engine's outbound octets (RST_STREAM, GOAWAY, SETTINGS/
//  PING ACK, WINDOW_UPDATE, response HEADERS/DATA) and express the two error granularities h2spec
//  distinguishes: a *connection* error (`receive` throws + GOAWAY, RFC 9113 §5.4.1) and a *stream*
//  error (`receive` does not throw; RST_STREAM is queued, §5.4.2). The builders live in `H2Wire.swift`.
//

import HPACK
import HTTPCore
import Testing

@testable import HTTP2

extension H2Wire {

    // MARK: Frame inspection

    /// Every complete frame in `bytes` (stops at the first incomplete/invalid tail).
    static func frames(in bytes: [UInt8]) -> [HTTP2FrameDecoder.Frame] {
        var out = [HTTP2FrameDecoder.Frame]()
        bytes.withUnsafeBytes { raw in
            var reader = ByteReader(raw)
            let decoder = HTTP2FrameDecoder()
            // `try?` flattens the throwing `Frame?` to one optional (SE-0230): the loop ends on the
            // first nil (no further complete frame) or any decode fault in the buffer.
            while let frame = try? decoder.nextFrame(&reader) {
                out.append(frame)
            }
        }
        return out
    }

    /// The first RST_STREAM frame's stream id and decoded error code, if any (§6.4).
    static func firstRst(in bytes: [UInt8]) -> (streamID: HTTP2StreamID, code: HTTP2ErrorCode)? {
        for frame in frames(in: bytes) where frame.header.type == .rstStream {
            guard frame.payload.count == 4 else { continue }
            return (frame.header.streamID, HTTP2ErrorCode(code: u32(frame.payload)))
        }
        return nil
    }

    /// The first GOAWAY frame's last-stream-id and decoded error code, if any (§6.8).
    static func firstGoAway(
        in bytes: [UInt8]
    ) -> (lastStreamID: HTTP2StreamID, code: HTTP2ErrorCode)? {
        for frame in frames(in: bytes) where frame.header.type == .goAway {
            guard frame.payload.count >= 8 else { continue }
            let last = u32(Array(frame.payload[0..<4]))
            let code = u32(Array(frame.payload[4..<8]))
            return (HTTP2StreamID(rawValue: last), HTTP2ErrorCode(code: code))
        }
        return nil
    }

    /// Whether a SETTINGS frame with the ACK flag was written (§6.5.3).
    static func hasSettingsAck(in bytes: [UInt8]) -> Bool {
        frames(in: bytes).contains { $0.header.type == .settings && $0.header.flags.contains(.ack) }
    }

    /// The payload of the first PING ACK written, if any (§6.7).
    static func pingAck(in bytes: [UInt8]) -> [UInt8]? {
        for frame in frames(in: bytes)
        where frame.header.type == .ping && frame.header.flags.contains(.ack) {
            return frame.payload
        }
        return nil
    }

    /// Every WINDOW_UPDATE written, as (stream, increment) pairs (§6.9).
    static func windowUpdates(in bytes: [UInt8]) -> [(streamID: HTTP2StreamID, increment: Int)] {
        frames(in: bytes)
            .filter { $0.header.type == .windowUpdate && $0.payload.count == 4 }
            .map { ($0.header.streamID, Int(u32($0.payload) & 0x7FFF_FFFF)) }
    }

    /// The concatenated DATA payload written, and whether any frame carried END_STREAM (§6.1).
    static func dataPayload(in bytes: [UInt8]) -> (bytes: [UInt8], endStream: Bool) {
        var data = [UInt8]()
        var endStream = false
        for frame in frames(in: bytes) where frame.header.type == .data {
            data += frame.payload
            if frame.header.flags.contains(.endStream) { endStream = true }
        }
        return (data, endStream)
    }

    /// The `:status` of the first response HEADERS block written, if any (§8.3.2).
    static func responseStatus(in bytes: [UInt8]) -> String? {
        var decoder = HPACKDecoder(maxDynamicTableSize: 4096)
        for frame in frames(in: bytes) where frame.header.type == .headers {
            guard
                let fragment = try? HTTP2HeadersFrame.fieldBlockFragment(
                    frame.payload, flags: frame.header.flags)
            else { continue }
            let fields =
                (try? Array(fragment).withUnsafeBytes { try decoder.decode($0.bytes) }) ?? []
            for field in fields where field.name == ":status" { return field.value }
        }
        return nil
    }

    /// Whether the bytes contain an RST_STREAM / GOAWAY (i.e. the engine rejected something).
    static func containsReset(in bytes: [UInt8]) -> Bool {
        frames(in: bytes).contains { $0.header.type == .rstStream }
    }
    static func containsGoAway(in bytes: [UInt8]) -> Bool {
        frames(in: bytes).contains { $0.header.type == .goAway }
    }

    // MARK: Assertions (h2spec's two error granularities)

    /// Asserts the engine accepted `bytes`: `receive` did not throw and queued no RST_STREAM/GOAWAY.
    static func expectAccepted(
        _ bytes: [UInt8],
        on connection: inout HTTP2Connection,
        sourceLocation: SourceLocation = #_sourceLocation
    ) {
        do {
            _ = try connection.receive(bytes)
            let out = connection.outboundBytes()
            #expect(
                !containsReset(in: out), "frame was rejected with RST_STREAM",
                sourceLocation: sourceLocation)
            #expect(
                !containsGoAway(in: out), "frame was rejected with GOAWAY",
                sourceLocation: sourceLocation)
        } catch {
            Issue.record(
                "expected the frame to be accepted, but a connection error \(error.code) was thrown",
                sourceLocation: sourceLocation)
        }
    }

    /// Asserts `bytes` complete a request: a `.request` event is emitted (the engine "responds").
    @discardableResult
    static func expectRequest(
        _ bytes: [UInt8],
        on connection: inout HTTP2Connection,
        sourceLocation: SourceLocation = #_sourceLocation
    ) -> HTTP2Connection.Event? {
        do {
            let events = try connection.receive(bytes)
            let request = events.first {
                guard case .request = $0 else { return false }
                return true
            }
            #expect(request != nil, "expected a request event", sourceLocation: sourceLocation)
            return request
        } catch {
            Issue.record(
                "expected a request, but a connection error \(error.code) was thrown",
                sourceLocation: sourceLocation)
            return nil
        }
    }

    /// Asserts a *connection* error (RFC 9113 §5.4.1): `receive` throws `code` and queues a GOAWAY.
    static func expectConnectionError(
        _ code: HTTP2ErrorCode,
        feeding bytes: [UInt8],
        on connection: inout HTTP2Connection,
        requireGoAway: Bool = true,
        sourceLocation: SourceLocation = #_sourceLocation
    ) {
        do {
            _ = try connection.receive(bytes)
            Issue.record(
                "expected connection error \(code), but receive did not throw",
                sourceLocation: sourceLocation)
        } catch {
            #expect(
                error.isConnectionError, "expected a connection-scoped error, got a stream error",
                sourceLocation: sourceLocation)
            #expect(
                error.code == code, "expected \(code), got \(error.code)",
                sourceLocation: sourceLocation)
            if requireGoAway {
                #expect(
                    firstGoAway(in: connection.outboundBytes())?.code == code,
                    "expected a GOAWAY carrying \(code)", sourceLocation: sourceLocation)
            }
        }
    }

    /// Asserts a *stream* error (RFC 9113 §5.4.2): `receive` does not throw; RST_STREAM `code` is queued.
    static func expectStreamError(
        _ code: HTTP2ErrorCode,
        on streamID: UInt32,
        feeding bytes: [UInt8],
        connection: inout HTTP2Connection,
        sourceLocation: SourceLocation = #_sourceLocation
    ) {
        do {
            _ = try connection.receive(bytes)
        } catch {
            Issue.record(
                "expected a stream error on \(streamID), but a connection error \(error.code) was thrown",
                sourceLocation: sourceLocation)
            return
        }
        let reset = firstRst(in: connection.outboundBytes())
        #expect(
            reset?.streamID == HTTP2StreamID(streamID), "expected RST_STREAM on stream \(streamID)",
            sourceLocation: sourceLocation)
        #expect(reset?.code == code, "expected RST_STREAM \(code)", sourceLocation: sourceLocation)
    }

    // MARK: Helpers

    /// Decodes the first four octets of `bytes` as a big-endian `UInt32`.
    private static func u32(_ bytes: [UInt8]) -> UInt32 {
        UInt32(bytes[0]) << 24 | UInt32(bytes[1]) << 16 | UInt32(bytes[2]) << 8 | UInt32(bytes[3])
    }
}
