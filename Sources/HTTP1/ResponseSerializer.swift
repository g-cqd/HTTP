//
//  ResponseSerializer.swift
//  HTTP1
//
//  RFC 9112 §3.1 / §5 — serializes an HTTPResponse onto the HTTP/1.1 wire (status-line + header
//  section + body). The body is auto-framed with Content-Length unless the caller already supplied
//  a framing header. Builds a single contiguous buffer to avoid intermediate allocations.
//

public import HTTPCore

/// Serializes an ``HTTPResponse`` into HTTP/1.1 wire bytes (RFC 9112).
public enum ResponseSerializer {
    private static let statusLinePrefix: [UInt8] = Array("HTTP/1.1 ".utf8)
    private static let crlf: [UInt8] = [0x0D, 0x0A]
    private static let space: UInt8 = 0x20
    private static let colon: UInt8 = 0x3A

    /// Standard reason-phrases for the common status codes (RFC 9110 §15).
    ///
    /// A data table, so it adds no branching; unregistered codes serialize with an empty
    /// reason-phrase (RFC 9112 §4 allows it).
    private static let reasonPhrases: [UInt16: StaticString] = [
        100: "Continue", 101: "Switching Protocols",
        200: "OK", 201: "Created", 202: "Accepted", 204: "No Content",
        301: "Moved Permanently", 302: "Found", 304: "Not Modified",
        400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
        405: "Method Not Allowed", 408: "Request Timeout", 413: "Content Too Large",
        414: "URI Too Long", 429: "Too Many Requests", 431: "Request Header Fields Too Large",
        500: "Internal Server Error", 501: "Not Implemented", 502: "Bad Gateway",
        503: "Service Unavailable", 505: "HTTP Version Not Supported"
    ]

    /// Serializes `response` and `body` into a complete HTTP/1.1 response message.
    ///
    /// When `omitBody` is `true` the body octets are not written, but `Content-Length` is still
    /// framed from `body.count` — the response to a `HEAD` request carries the same header section
    /// as the equivalent `GET` would, with no body (RFC 9112 §6.3).
    public static func serialize(
        _ response: HTTPResponse,
        body: [UInt8] = [],
        omitBody: Bool = false
    ) -> [UInt8] {
        var output: [UInt8] = []
        output.reserveCapacity(64 + (omitBody ? 0 : body.count))

        // Status-line: HTTP-version SP status-code SP [ reason-phrase ] CRLF (RFC 9112 §3.1).
        output.append(contentsOf: statusLinePrefix)
        appendStatusCode(response.status.code, to: &output)
        output.append(space)
        appendReasonPhrase(for: response.status, to: &output)
        output.append(contentsOf: crlf)

        // Auto-frame the body with Content-Length unless a framing header is already present, or the
        // status forbids content — 1xx / 204 / 304 carry no body and MUST NOT be framed (RFC 9110
        // §6.4.1), which is also what lets a 101 hand the connection cleanly to WebSocket.
        var fields = response.headerFields
        if !Self.forbidsContent(response.status), !fields.contains(.contentLength),
            !fields.contains(.transferEncoding)
        {
            fields.append("\(body.count)", for: .contentLength)
        }
        for field in fields {
            field.name.appendRawNameUTF8(to: &output)
            output.append(colon)
            output.append(space)
            output.append(contentsOf: field.value.utf8)
            output.append(contentsOf: crlf)
        }
        output.append(contentsOf: crlf)  // blank line terminates the header section

        if !omitBody { output.append(contentsOf: body) }
        return output
    }

    /// Whether `status` forbids a response body: 1xx Informational, 204 No Content, 304 Not Modified
    /// (RFC 9110 §6.4.1) — none may carry Content-Length.
    private static func forbidsContent(_ status: HTTPStatus) -> Bool {
        (100 ..< 200).contains(status.code) || status.code == 204 || status.code == 304
    }

    /// Appends a status code's three decimal digits (the code is an invariant `100...599`).
    private static func appendStatusCode(_ code: UInt16, to output: inout [UInt8]) {
        output.append(0x30 &+ UInt8(code / 100 % 10))
        output.append(0x30 &+ UInt8(code / 10 % 10))
        output.append(0x30 &+ UInt8(code % 10))
    }

    /// Appends the registered reason-phrase for `status`, or nothing if the code is unregistered.
    private static func appendReasonPhrase(for status: HTTPStatus, to output: inout [UInt8]) {
        guard let phrase = reasonPhrases[status.code] else { return }
        phrase.withUTF8Buffer { output.append(contentsOf: $0) }
    }
}
