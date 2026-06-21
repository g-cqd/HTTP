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
    /// terminating CRLF and rejecting a line longer than `maxLength`, or throws the specific
    /// ``HTTP1ParseError``.
    public static func parse(
        _ reader: inout ByteReader,
        maxLength: Int = .max
    ) throws(HTTP1ParseError) -> RequestLine {
        let start = reader.position
        guard let methodRange = reader.readSlice(until: space) else { throw .malformedRequestLine }
        guard let targetRange = reader.readSlice(until: space) else { throw .malformedRequestLine }
        guard let versionRange = reader.readSlice(until: carriageReturn) else {
            throw .malformedRequestLine
        }
        // The request-line MUST terminate with CRLF; a bare CR is a framing error (RFC 9112 §2.2).
        guard reader.readByte() == lineFeed else { throw .malformedRequestLine }
        // Enforce the length budget BEFORE materializing any component (RFC 9112 §3; → 414).
        guard reader.position - start <= maxLength else { throw .requestLineTooLong }

        guard let method = HTTPMethod(rawValue: reader.string(in: methodRange)) else {
            throw .invalidMethod
        }
        // Validate the borrowed target bytes BEFORE materializing them: a non-empty target free of
        // controls / DEL / whitespace. Rejecting controls closes request-line injection (a target
        // such as "/a\rb" or "/a\u{00}b" must never reach a String or downstream log).
        guard isValidRequestTarget(reader.slice(in: targetRange)) else { throw .invalidTarget }
        let target = reader.string(in: targetRange)
        guard let version = HTTPVersion(parsing: reader.slice(in: versionRange)) else {
            throw .unsupportedVersion
        }
        return RequestLine(method: method, target: target, version: version)
    }

    /// Whether `target` is a non-empty request-target free of controls, DEL, and whitespace
    /// (RFC 9112 §3.2) — the octets that enable request-line injection / smuggling.
    private static func isValidRequestTarget(_ target: RawSpan) -> Bool {
        let count = target.byteCount
        guard count > 0 else { return false }
        var index = 0
        while index < count {
            let byte = target.unsafeLoad(fromByteOffset: index, as: UInt8.self)
            guard byte > 0x20, byte != 0x7F else { return false }  // reject CTL, SP, and DEL
            index += 1
        }
        return true
    }
}
