//
//  HTTP3FrameWriter.swift
//  HTTP3
//
//  RFC 9114 §7.1 — the outbound frame encoder: a frame is its variable-length Type, its
//  variable-length Length, and the payload octets. Factored out so the connection engine and the
//  response encoder share one byte-layout helper.
//

internal import HTTPCore

/// Serializes outbound HTTP/3 frames (RFC 9114 §7.1).
enum HTTP3FrameWriter {

    /// Encodes a complete frame (Type, Length, payload) into a new buffer.
    static func frame(_ type: HTTP3FrameType, payload: [UInt8]) -> [UInt8] {
        var output = [UInt8]()
        QUICVarint.encode(type.rawValue, into: &output)
        QUICVarint.encode(UInt64(payload.count), into: &output)
        output.append(contentsOf: payload)
        return output
    }

    /// Appends a complete frame (Type, Length, payload) to `output`.
    static func append(_ type: HTTP3FrameType, payload: [UInt8], to output: inout [UInt8]) {
        QUICVarint.encode(type.rawValue, into: &output)
        QUICVarint.encode(UInt64(payload.count), into: &output)
        output.append(contentsOf: payload)
    }
}
