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
        var out = [UInt8]()
        QUICVarint.encode(value, into: &out)
        return out
    }

    /// A complete HTTP/3 frame (Type, Length, payload).
    func frame(_ type: HTTP3FrameType, _ payload: [UInt8] = []) -> [UInt8] {
        HTTP3FrameWriter.frame(type, payload: payload)
    }

    /// A SETTINGS payload from (identifier, value) pairs.
    func settingsPayload(_ pairs: [(UInt64, UInt64)]) -> [UInt8] {
        var out = [UInt8]()
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
            HeaderField(name: ":path", value: path),
        ]
        fields.append(contentsOf: extra)
        return QPACKEncoder().encode(fields)
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
        } catch {
            return (error as? HTTP3Error)?.code
        }
    }

    /// The error code of the first queued `closeConnection` action, if any.
    func closeConnectionCode(_ connection: inout HTTP3Connection) -> UInt64? {
        for action in connection.outbound() {
            if case .closeConnection(let errorCode) = action { return errorCode }
        }
        return nil
    }
}
