//
//  StatusLineParser.swift
//  HTTP1
//
//  RFC 9112 §4 — parses the HTTP/1.x status-line
//  (`HTTP-version SP status-code SP [ reason-phrase ] CRLF`). Zero-copy over `ByteReader`, trap-free.
//

internal import AemiKernel
public import HTTPCore

/// Parses the HTTP/1.x status-line (RFC 9112 §4).
public enum StatusLineParser {
    /// `"HTTP/1.1 200 "` — the shortest legal status-line before CRLF (the SP after the code is
    /// required even when the reason-phrase is empty).
    private static let minimumLength = 13

    /// Parses one status-line from `reader`, returning its version and status.
    ///
    /// Throws ``HTTP1ParseError/incompleteHeaders`` while the CRLF has not arrived, so a caller can
    /// read more and retry; every other failure is ``HTTP1ParseError/malformedStatusLine`` (or
    /// ``HTTP1ParseError/unsupportedVersion`` for a non-1.x version).
    public static func parse(
        _ reader: inout HTTPCore.ByteReader,
        maxLength limit: Int = .max
    ) throws(HTTP1ParseError) -> (version: HTTPVersion, status: HTTPStatus) {
        let lineStart = reader.position
        guard let range = reader.readSlice(until: 0x0D) else {
            throw .incompleteHeaders
        }
        guard let terminator = reader.readByte() else {
            throw .incompleteHeaders
        }
        guard terminator == 0x0A, reader.position - lineStart <= limit else {
            throw .malformedStatusLine
        }
        let line = reader.slice(in: range)
        guard line.byteCount >= minimumLength, line.loadU8(8) == 0x20, line.loadU8(12) == 0x20,
            let version = HTTPVersion(parsing: line.extracting(0 ..< 8))
        else {
            throw .malformedStatusLine
        }
        guard version == .http11 || version == .http10 else {
            throw .unsupportedVersion
        }
        var code = 0
        for offset in 9 ..< 12 {
            let digit = line.loadU8(offset)
            guard digit >= 0x30, digit <= 0x39 else {
                throw .malformedStatusLine
            }
            code = code * 10 + Int(digit - 0x30)
        }
        guard let status = HTTPStatus(code: code) else {
            throw .malformedStatusLine
        }
        // reason-phrase = 1*( HTAB / SP / VCHAR / obs-text ): no controls may hide in it.
        if line.byteCount > minimumLength,
            !FieldValidation.isValidFieldValue(line.extracting(minimumLength ..< line.byteCount))
        {
            throw .malformedStatusLine
        }
        return (version, status)
    }
}
