//
//  ResponseParser.swift
//  HTTP1
//
//  RFC 9112 §4 / §5 / §6.3 — parses an HTTP/1.x response head and resolves its message-body framing,
//  enforcing the `Content-Length` + `Transfer-Encoding` smuggling ban (§6.3 rule 3).
//

public import HTTPCore

/// Parses HTTP/1.x response heads and resolves RFC 9112 §6.3 body framing.
public enum ResponseParser {
    /// Parses the status-line and header section (not the body) from `reader`, resolving framing
    /// against the originating `forRequestMethod` (`HEAD` carries no body on the wire, §6.3 rule 1).
    public static func parseHead(
        _ reader: inout HTTPCore.ByteReader,
        forRequestMethod requestMethod: HTTPMethod = .get,
        limits: HTTPLimits = .default
    ) throws(HTTP1ParseError) -> ResponseHead {
        let (version, status) = try StatusLineParser.parse(
            &reader,
            maxLength: limits.maxRequestLineLength
        )
        let headerFields = try HeaderParser.parse(&reader, limits: limits)
        let framing = try resolveFraming(
            headerFields,
            version: version,
            status: status,
            requestMethod: requestMethod,
            limits: limits
        )
        return (HTTPResponse(status: status, headerFields: headerFields), version, framing)
    }

    /// Resolves RFC 9112 §6.3 response body framing.
    public static func resolveFraming(
        _ headerFields: HTTPFields,
        version: HTTPVersion,
        status: HTTPStatus,
        requestMethod: HTTPMethod,
        limits: HTTPLimits
    ) throws(HTTP1ParseError) -> ResponseBodyFraming {
        // RFC 9112 §6.3 rules 1–2: HEAD, 1xx, 204, and 304 never carry a message body on the wire,
        // regardless of header fields — Check CL+TE smuggling first when both are present.
        if headerFields.contains(.transferEncoding), headerFields.contains(.contentLength) {
            throw .contentLengthWithTransferEncoding
        }
        if requestMethod == .head
            || (100 ..< 200).contains(status.code)
            || status.code == 204
            || status.code == 304
        {
            return .none
        }
        switch try RequestParser.resolveFraming(headerFields, version: version, limits: limits) {
            case .chunked:
                return .chunked
            case .contentLength(let length):
                return .contentLength(length)
            case .none:
                return .untilEOF
        }
    }
}
