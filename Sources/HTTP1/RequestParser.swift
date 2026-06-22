//
//  RequestParser.swift
//  HTTP1
//
//  RFC 9112 — assembles a full HTTP/1.1 request (request-line + headers + body). This is where the
//  request-smuggling defenses come together: Content-Length vs Transfer-Encoding precedence
//  (§6.1/§6.3) and the mandatory Host header (RFC 9110 §7.2).
//

public import HTTPCore

/// Parses a complete HTTP/1.1 request message (RFC 9112).
public enum RequestParser {

    private static let chunkedToken: [UInt8] = Array("chunked".utf8)

    /// Parses request-line, header section, and body from `reader`, returning the assembled
    /// ``ParsedRequest`` — or throws the specific ``HTTP1ParseError``.
    public static func parse(
        _ reader: inout ByteReader,
        limits: HTTPLimits
    ) throws(HTTP1ParseError) -> ParsedRequest {
        let requestLine = try RequestLineParser.parse(
            &reader, maxLength: limits.maxRequestLineLength)

        let headerFields = try HeaderParser.parse(&reader, limits: limits)

        // RFC 9110 §7.2: an HTTP/1.1 request MUST carry exactly one valid Host.
        if requestLine.version == .http11, headerFields.count(for: .host) != 1 {
            throw .invalidHost
        }

        let body = try decodeBody(&reader, headerFields: headerFields, limits: limits)
        let request = HTTPRequest(
            method: requestLine.method,
            authority: headerFields[.host],
            path: requestLine.target,
            headerFields: headerFields
        )
        return ParsedRequest(request: request, body: body, version: requestLine.version)
    }

    /// Resolves the message body framing (RFC 9112 §6): Transfer-Encoding takes precedence over
    /// Content-Length, the two together are a smuggling error, and the only supported coding is the
    /// final `chunked`.
    private static func decodeBody(
        _ reader: inout ByteReader,
        headerFields: HTTPFields,
        limits: HTTPLimits
    ) throws(HTTP1ParseError) -> [UInt8] {
        if headerFields.contains(.transferEncoding) {
            guard !headerFields.contains(.contentLength) else {
                throw .contentLengthWithTransferEncoding
            }
            guard isChunked(headerFields[.transferEncoding]) else {
                throw .unsupportedTransferEncoding
            }
            return try ChunkedDecoder.decode(&reader, limits: limits)
        }

        switch headerFields.contentLength {
        case .absent:
            return []
        case .invalid:
            throw .invalidContentLength
        case .length(let length):
            guard length <= limits.maxBodySize else { throw .bodyTooLarge }
            guard reader.remaining >= length else { throw .incompleteBody }
            let start = reader.position
            reader.advance(by: length)
            return reader.slice(in: start..<(start + length)).withUnsafeBytes { Array($0) }
        }
    }

    /// Whether `value` is exactly the `chunked` transfer-coding (case-insensitive, OWS-trimmed).
    ///
    /// Any other or compound coding (e.g. `gzip, chunked`, or `chunked, chunked`) returns `false`,
    /// so the caller rejects it rather than guessing the body length (RFC 9112 §6.1).
    private static func isChunked(_ value: String?) -> Bool {
        guard let value else { return false }
        let utf8 = value.utf8
        var start = utf8.startIndex
        var end = utf8.endIndex
        while start < end, isOptionalWhitespace(utf8[start]) { start = utf8.index(after: start) }
        while end > start, isOptionalWhitespace(utf8[utf8.index(before: end)]) {
            end = utf8.index(before: end)
        }

        var index = start
        var position = 0
        while index < end {
            guard position < chunkedToken.count else { return false }
            let byte = utf8[index]
            let lowered = byte >= 0x41 && byte <= 0x5A ? byte &+ 0x20 : byte
            guard lowered == chunkedToken[position] else { return false }
            index = utf8.index(after: index)
            position += 1
        }
        return position == chunkedToken.count
    }

    private static func isOptionalWhitespace(_ byte: UInt8) -> Bool {
        byte == 0x20 || byte == 0x09
    }
}
