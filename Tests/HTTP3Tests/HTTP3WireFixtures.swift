//
//  HTTP3WireFixtures.swift
//  HTTP3Tests
//
//  Wire builders shared by the HTTP/3 connection-engine tests: helpers that assemble RFC 9114
//  unidirectional-stream preambles and frames (SETTINGS, GOAWAY, CANCEL_PUSH, MAX_PUSH_ID, DATA,
//  HEADERS) and QPACK instruction-stream bytes, mirroring the HTTP/2 `HTTP2WireFixtures` pattern.
//

import HTTPCore
import QPACK

@testable import HTTP3

/// Wire builders for the HTTP/3 connection-engine test suites.
protocol HTTP3WireFixtures {}

extension HTTP3WireFixtures {
    /// A single QUIC variable-length integer, as a byte sequence.
    func varint(_ value: UInt64) -> [UInt8] {
        var out: [UInt8] = []
        QUICVarint.encode(value, into: &out)
        return out
    }

    /// A complete HTTP/3 frame (Type, Length, payload).
    func frame(_ type: HTTP3FrameType, _ payload: [UInt8] = []) -> [UInt8] {
        HTTP3FrameWriter.frame(type, payload: payload)
    }

    /// A SETTINGS payload from (identifier, value) pairs.
    func settingsPayload(_ pairs: [(UInt64, UInt64)]) -> [UInt8] {
        var out: [UInt8] = []
        for (identifier, value) in pairs {
            QUICVarint.encode(identifier, into: &out)
            QUICVarint.encode(value, into: &out)
        }
        return out
    }

    /// The control-stream preamble: the §6.2 type byte (0x00) followed by a SETTINGS frame.
    func controlPreamble(_ pairs: [(UInt64, UInt64)] = [(0x01, 0), (0x07, 0)]) -> [UInt8] {
        [0x00] + frame(.settings, settingsPayload(pairs))
    }

    /// A QPACK-encoded field section from an explicit field list (may be intentionally malformed).
    func fieldSection(_ fields: [HeaderField]) -> [UInt8] {
        QPACKEncoder().encode(fields)
    }

    /// A QPACK-encoded request field section (RIC=0, Base=0) for a simple GET.
    func requestFieldSection(
        method: String = "GET",
        scheme: String = "https",
        authority: String = "example.com",
        path: String = "/",
        extra: [HeaderField] = []
    ) -> [UInt8] {
        var fields = [
            HeaderField(name: ":method", value: method),
            HeaderField(name: ":scheme", value: scheme),
            HeaderField(name: ":authority", value: authority),
            HeaderField(name: ":path", value: path)
        ]
        fields.append(contentsOf: extra)
        return QPACKEncoder().encode(fields)
    }

    /// The bytes of a request stream: a HEADERS frame and, optionally, a DATA frame.
    func requestStream(_ section: [UInt8], body: [UInt8]? = nil) -> [UInt8] {
        var out = frame(.headers, section)
        if let body { out += frame(.data, body) }
        return out
    }

    /// The error code of the first queued `resetStream` action, if any (a stream-scoped error).
    func resetStreamCode(_ connection: inout HTTP3Connection) -> UInt64? {
        for action in connection.outbound() {
            if case .resetStream(_, let errorCode) = action {
                return errorCode
            }
        }
        return nil
    }

    /// The bytes and FIN of the first queued `send` action for `streamID`.
    func sentBytes(
        _ connection: inout HTTP3Connection, on streamID: QUICStreamID
    ) -> (bytes: [UInt8], fin: Bool)? {
        for action in connection.outbound() {
            if case .send(.id(let id), let bytes, let fin) = action, id == streamID {
                return (bytes, fin)
            }
        }
        return nil
    }

    /// Decodes a server response off the wire: the `:status` and the concatenated DATA.
    func decodeResponse(_ bytes: [UInt8]) throws -> (status: String?, body: [UInt8]) {
        var status: String?
        var body: [UInt8] = []
        try bytes.withUnsafeBytes { raw in
            var reader = ByteReader(raw)
            let frames = HTTP3FrameDecoder(maxFrameSize: 1 << 20)
            while let next = try frames.nextFrame(&reader) {
                switch next.type {
                    case .headers:
                        let fields = try next.payload.withUnsafeBytes {
                            try QPACKDecoder().decode($0.bytes)
                        }
                        for field in fields where field.name == ":status" { status = field.value }
                    case .data:
                        body.append(contentsOf: next.payload)
                    default:
                        break
                }
            }
        }
        return (status, body)
    }

    /// Feeds `bytes` for `stream` and returns the thrown error's code, or nil if none was thrown.
    func errorCode(
        feeding connection: inout HTTP3Connection,
        _ stream: QUICStreamID,
        _ bytes: [UInt8],
        fin: Bool = false
    ) -> UInt64? {
        do {
            _ = try connection.receive(stream, bytes, fin: fin)
            return nil
        }
        catch {
            return error.code
        }
    }

    /// The error code of the first queued `closeConnection` action, if any.
    func closeConnectionCode(_ connection: inout HTTP3Connection) -> UInt64? {
        for action in connection.outbound() {
            if case .closeConnection(let errorCode) = action {
                return errorCode
            }
        }
        return nil
    }
}
