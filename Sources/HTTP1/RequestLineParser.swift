//
//  RequestLineParser.swift
//  HTTP1
//
//  RFC 9112 §3 — parses the request-line. Iterative and zero-copy: it reads byte ranges from a
//  `ByteReader` and materializes owned strings only for the parsed components.
//

public import HTTPCore

/// Parses the HTTP/1.1 request-line (RFC 9112 §3).
public enum RequestLineParser {

    private static let space: UInt8 = 0x20
    private static let carriageReturn: UInt8 = 0x0D
    private static let lineFeed: UInt8 = 0x0A

    /// Parses `method SP request-target SP HTTP-version CRLF` from `reader`, advancing it past the
    /// terminating CRLF, or throws the specific ``HTTP1ParseError``.
    public static func parse(_ reader: inout ByteReader) throws(HTTP1ParseError) -> RequestLine {
        guard let methodRange = reader.readSlice(until: space) else { throw .malformedRequestLine }
        guard let targetRange = reader.readSlice(until: space) else { throw .malformedRequestLine }
        guard let versionRange = reader.readSlice(until: carriageReturn) else {
            throw .malformedRequestLine
        }
        // The request-line MUST terminate with CRLF; a bare CR is a framing error (RFC 9112 §2.2).
        guard reader.readByte() == lineFeed else { throw .malformedRequestLine }

        guard let method = HTTPMethod(rawValue: reader.string(in: methodRange)) else {
            throw .invalidMethod
        }
        let target = reader.string(in: targetRange)
        guard !target.isEmpty else { throw .invalidTarget }
        guard let version = HTTPVersion(parsing: reader.slice(in: versionRange)) else {
            throw .unsupportedVersion
        }
        return RequestLine(method: method, target: target, version: version)
    }
}
