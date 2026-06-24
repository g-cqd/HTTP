//
//  ChunkedDecoder.swift
//  HTTP1
//
//  RFC 9112 §7.1 — the one-shot chunked transfer-coding decoder, for callers that already hold the
//  whole body. It is a thin wrapper over the resumable ``ChunkedBodyDecoder`` so both paths share one
//  implementation (including the §7.1.1 chunk-extension bound and the §7.1.2 trailer validation); a
//  body that is not yet complete surfaces as ``HTTP1ParseError/incompleteBody``.
//

public import HTTPCore

/// Decodes the HTTP/1.1 chunked transfer-coding in a single pass (RFC 9112 §7.1).
public enum ChunkedDecoder {
    /// Decodes the chunked body at `reader` (size CRLF data CRLF … last-chunk trailers CRLF), advancing
    /// past it, and returns the assembled body — or throws an ``HTTP1ParseError``.
    public static func decode(
        _ reader: inout ByteReader,
        limits: HTTPLimits
    ) throws(HTTP1ParseError) -> [UInt8] {
        var state = ChunkedBodyDecoder.State()
        var body: [UInt8] = []
        let complete = try ChunkedBodyDecoder.advance(
            &reader,
            state: &state,
            into: &body,
            limits: limits
        )
        guard complete else { throw .incompleteBody }
        return body
    }
}
