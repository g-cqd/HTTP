//
//  RequestSerializer.swift
//  HTTP1
//
//  RFC 9112 §3 / §5 — serializes a client `HTTPRequest` onto the HTTP/1.1 wire, validating the
//  method token, origin-form request-target, mandatory `Host` authority, and every field value so
//  outbound traffic can carry no CRLF / header injection or smuggled framing.
//

public import HTTPCore

/// Serializes client ``HTTPRequest`` messages onto the HTTP/1.1 wire (RFC 9112 §3 / §5).
public enum RequestSerializer {
    private static let protocolSuffix: [UInt8] = Array(" HTTP/1.1".utf8)

    /// Serializes `request` and `body` into a complete HTTP/1.1 request message.
    public static func serialize(
        _ request: HTTPRequest,
        body: [UInt8] = []
    ) throws(HTTP1ParseError) -> [UInt8] {
        var output: [UInt8] = []
        try serializeHead(request, bodyLength: body.count, into: &output)
        output.append(contentsOf: body)
        return output
    }

    /// Serializes only the request head (request-line, header section, blank line) into `output`,
    /// clearing it first; `Host` is derived from the authority and `Content-Length` from
    /// `bodyLength` when the request does not already frame itself.
    public static func serializeHead(
        _ request: HTTPRequest,
        bodyLength: Int,
        into output: inout [UInt8]
    ) throws(HTTP1ParseError) {
        output.removeAll(keepingCapacity: true)
        let fields = try validatedFields(request, bodyLength: bodyLength)
        output.reserveCapacity(64 + request.path.utf8.count)
        // request-line = method SP request-target SP HTTP-version CRLF (RFC 9112 §3)
        output.append(contentsOf: request.method.rawValue.utf8)
        output.append(HeaderSectionWriter.space)
        output.append(contentsOf: request.path.utf8)
        output.append(contentsOf: protocolSuffix)
        output.append(contentsOf: HeaderSectionWriter.crlf)
        HeaderSectionWriter.append(fields, to: &output)
    }

    /// Validates every outbound component and returns the header section to emit (`Host` first).
    private static func validatedFields(
        _ request: HTTPRequest,
        bodyLength: Int
    ) throws(HTTP1ParseError) -> HTTPFields {
        guard FieldValidation.isToken(request.method.rawValue.utf8) else {
            throw .invalidMethod
        }
        let target = request.path.utf8
        guard !target.isEmpty, FieldValidation.isRequestTargetValue(target) else {
            throw .invalidTarget
        }
        guard let host = request.effectiveAuthority, !host.isEmpty,
            RequestParser.isValidHostValue(host)
        else {
            throw .invalidHost  // RFC 9112 §3.2: a client MUST send Host
        }
        var fields = HTTPFields()
        fields.reserveCapacity(request.headerFields.count + 2)
        if !request.headerFields.contains(.host) {
            fields.append(host, for: .host)
        }
        for field in request.headerFields {
            guard FieldValidation.isValidFieldValue(field.value.utf8) else {
                throw .invalidFieldValue
            }
            fields.append(field)
        }
        let framed = fields.contains(.contentLength) || fields.contains(.transferEncoding)
        if bodyLength > 0, !framed {
            fields.append("\(bodyLength)", for: .contentLength)
        }
        return fields
    }
}
