//
//  HTTP2ConnectionPreface.swift
//  HTTP2
//
//  RFC 9113 §3.4 — the client connection preface. A cleartext or TLS HTTP/2 connection opens with the
//  client sending the 24-octet sequence "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", followed by its SETTINGS
//  frame. The server validates the magic before processing any frame; a mismatch is not HTTP/2.
//

public import HTTPCore

/// The RFC 9113 §3.4 client connection preface (the 24-octet magic that opens every connection).
public enum HTTP2ConnectionPreface {

    /// The fixed 24-octet client preface (RFC 9113 §3.4).
    public static let client = Array("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8)

    /// The outcome of matching the preface against the bytes received so far.
    public enum MatchResult: Sendable, Equatable {

        /// The full 24-octet preface was present and consumed.
        case matched

        /// The bytes so far are a valid prefix, but the full preface has not arrived yet.
        case incomplete
    }

    /// Matches and consumes the client preface from `reader` (RFC 9113 §3.4).
    ///
    /// Consumes and returns `.matched` once all 24 octets are present; returns `.incomplete` (without
    /// consuming) while a valid prefix is still arriving; throws PROTOCOL_ERROR on the first
    /// mismatching octet.
    public static func consume(_ reader: inout ByteReader) throws(HTTP2Error) -> MatchResult {
        let available = min(reader.remaining, client.count)
        var probe = reader
        var index = 0
        while index < available {
            guard probe.readByte() == client[index] else {
                throw .connection(.protocolError, "invalid HTTP/2 connection preface")
            }
            index += 1
        }
        guard reader.remaining >= client.count else { return .incomplete }
        reader.advance(by: client.count)
        return .matched
    }
}
