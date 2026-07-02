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
        serialize(response, body: body, omitBody: omitBody, into: &output)
        return output
    }

    /// Serializes `response` and `body` into `output`, **reusing its existing storage**.
    ///
    /// `output` is cleared keeping capacity, so a per-connection buffer threaded through the keep-alive
    /// loop serializes every response with no fresh allocation after the first (audit: tail-latency
    /// variance — fewer per-request mallocs means less allocator-lock contention, which tightens the
    /// tail). Behaviourally identical to ``serialize(_:body:omitBody:)``.
    public static func serialize(
        _ response: HTTPResponse,
        body: [UInt8] = [],
        omitBody: Bool = false,
        into output: inout [UInt8]
    ) {
        // Serialize the head, then append the body in place when the status/method allow one.
        let sendsBody = serializeHead(
            response,
            bodyLength: body.count,
            omitBody: omitBody,
            into: &output
        )
        if sendsBody { output.append(contentsOf: body) }
    }

    /// Serializes only the response **head** (status-line + header section + terminating CRLF) into
    /// `output`, framing `Content-Length` from `bodyLength`; the body is sent separately.
    ///
    /// Returns whether the caller should still write the `bodyLength` body octets — `false` for a `HEAD`
    /// response (`omitBody`) or a body-forbidden status (1xx / 204 / 304, RFC 9110 §6.4.1). This is the
    /// scatter-gather entry point: a `writev` send can put the head and the untouched body buffer on the
    /// wire in one syscall, with no coalesce copy (audit #4 / L4); ``serialize(_:body:omitBody:into:)``
    /// is the coalescing wrapper. `output` is cleared keeping capacity (the per-connection reuse, CC6).
    public static func serializeHead(
        _ response: HTTPResponse,
        bodyLength: Int,
        omitBody: Bool = false,
        into output: inout [UInt8]
    ) -> Bool {
        output.removeAll(keepingCapacity: true)
        output.reserveCapacity(64)

        // Status-line: HTTP-version SP status-code SP [ reason-phrase ] CRLF (RFC 9112 §3.1).
        output.append(contentsOf: statusLinePrefix)
        appendStatusCode(response.status.code, to: &output)
        output.append(space)
        appendReasonPhrase(for: response.status, to: &output)
        output.append(contentsOf: crlf)

        // Auto-frame the body with Content-Length unless a framing header is already present, or the
        // status forbids content — 1xx / 204 / 304 carry no body and MUST NOT be framed (RFC 9110
        // §6.4.1), which is also what lets a 101 hand the connection cleanly to WebSocket.
        let forbids = Self.forbidsContent(response.status)
        var fields = response.headerFields
        if !forbids, !fields.contains(.contentLength), !fields.contains(.transferEncoding) {
            fields.append("\(bodyLength)", for: .contentLength)
        }
        for field in fields {
            field.name.appendRawNameUTF8(to: &output)
            output.append(colon)
            output.append(space)
            output.append(contentsOf: field.value.utf8)
            output.append(contentsOf: crlf)
        }
        output.append(contentsOf: crlf)  // blank line terminates the header section

        // A body-forbidden status (1xx/204/304) or a HEAD response writes no body octets: an unframed
        // body on a keep-alive connection would be read as the next response's start (RFC 9110 §6.4.1).
        return !omitBody && !forbids
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

    /// Appends the registered reason-phrase for `status`, or nothing if the code is unregistered
    /// (RFC 9112 §4 allows an empty reason-phrase).
    ///
    /// The table is ``HTTPStatus/reasonPhrase`` — one registry serves the public API and this
    /// status-line; the strings are literals in constant storage, so the append copies bytes without
    /// allocating.
    private static func appendReasonPhrase(for status: HTTPStatus, to output: inout [UInt8]) {
        guard let phrase = status.reasonPhrase else {
            return
        }
        output.append(contentsOf: phrase.utf8)
    }
}
