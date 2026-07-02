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
    ///
    /// This one-shot form enforces the global ``HTTPLimits/maxBodySize`` on a declared
    /// `Content-Length` before decoding (RFC 9110 §15.5.14). The incremental server path enforces the
    /// *route-resolved* limit instead — resolution needs the parsed head, so the policy runs after
    /// ``parseHead(_:limits:)``, not inside it (Phase 1.2: a route cap replaces the global bound).
    public static func parse(
        _ reader: inout ByteReader,
        limits: HTTPLimits
    ) throws(HTTP1ParseError) -> ParsedRequest {
        let head = try parseHead(&reader, limits: limits)
        if case .contentLength(let length) = head.framing, length > limits.maxBodySize {
            throw .bodyTooLarge
        }
        let body = try decodeBody(&reader, framing: head.framing, limits: limits)
        return ParsedRequest(request: head.request, body: body, version: head.version)
    }

    /// Parses the request-line and header section (not the body), validating the mandatory Host and
    /// resolving the body framing (RFC 9112 §6) so the body can be read incrementally afterward.
    public static func parseHead(
        _ reader: inout ByteReader,
        limits: HTTPLimits
    ) throws(HTTP1ParseError) -> RequestHead {
        let requestLine = try RequestLineParser.parse(
            &reader,
            maxLength: limits.maxRequestLineLength
        )
        let headerFields = try HeaderParser.parse(&reader, limits: limits)

        // RFC 9110 §7.2: an HTTP/1.1 request MUST carry exactly one valid Host.
        if requestLine.version == .http11, headerFields.count(for: .host) != 1 {
            throw .invalidHost
        }

        let framing = try resolveFraming(headerFields, version: requestLine.version, limits: limits)
        let request = HTTPRequest(
            method: requestLine.method,
            authority: headerFields[.host],
            path: requestLine.target,
            headerFields: headerFields
        )
        return RequestHead(request: request, version: requestLine.version, framing: framing)
    }

    /// Resolves the body framing without decoding (RFC 9112 §6): Transfer-Encoding takes precedence
    /// over Content-Length, the two together are a smuggling error, and the only supported coding is
    /// the final `chunked`.
    ///
    /// Framing resolution carries **no size policy**: a syntactically valid `Content-Length` of any
    /// magnitude resolves to ``BodyFraming/contentLength(_:)``, and the caller enforces its limit —
    /// global or route-resolved (Phase 1.2) — before buffering a byte. The declared length is only a
    /// number; nothing is allocated from it here.
    public static func resolveFraming(
        _ headerFields: HTTPFields,
        version: HTTPVersion,
        limits _: HTTPLimits
    ) throws(HTTP1ParseError) -> BodyFraming {
        if headerFields.contains(.transferEncoding) {
            // Chunked is an HTTP/1.1 feature (RFC 9112 §6.1); a Transfer-Encoding on a nominal
            // HTTP/1.0 message is a classic front-end/back-end discrepancy used in request smuggling —
            // reject it rather than honor a coding the version cannot carry (audit H1-F5).
            guard version == .http11 else { throw .unsupportedTransferEncoding }
            guard !headerFields.contains(.contentLength) else {
                throw .contentLengthWithTransferEncoding
            }
            guard isChunked(headerFields[.transferEncoding]) else {
                throw .unsupportedTransferEncoding
            }
            return .chunked
        }
        switch headerFields.contentLength {
            case .absent:
                return .none
            case .invalid:
                throw .invalidContentLength
            case .length(let length):
                return .contentLength(length)
        }
    }

    /// Decodes the body for an already-resolved `framing` (RFC 9112 §6).
    private static func decodeBody(
        _ reader: inout ByteReader,
        framing: BodyFraming,
        limits: HTTPLimits
    ) throws(HTTP1ParseError) -> [UInt8] {
        switch framing {
            case .none:
                return []
            case .contentLength(let length):
                guard reader.remaining >= length else { throw .incompleteBody }
                let start = reader.position
                reader.advance(by: length)
                return reader.slice(in: start ..< (start + length)).withUnsafeBytes { Array($0) }
            case .chunked:
                return try ChunkedDecoder.decode(&reader, limits: limits)
        }
    }

    /// Whether `value` is exactly the `chunked` transfer-coding (case-insensitive, OWS-trimmed).
    ///
    /// Any other or compound coding (e.g. `gzip, chunked`, or `chunked, chunked`) returns `false`,
    /// so the caller rejects it rather than guessing the body length (RFC 9112 §6.1).
    private static func isChunked(_ value: String?) -> Bool {
        guard let value else {
            return false
        }
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
            guard position < chunkedToken.count else {
                return false
            }
            let byte = utf8[index]
            let lowered = byte >= 0x41 && byte <= 0x5A ? byte &+ 0x20 : byte
            guard lowered == chunkedToken[position] else {
                return false
            }
            index = utf8.index(after: index)
            position += 1
        }
        return position == chunkedToken.count
    }

    private static func isOptionalWhitespace(_ byte: UInt8) -> Bool {
        byte == 0x20 || byte == 0x09
    }
}
