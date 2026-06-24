//
//  HTTP2RequestMapper.swift
//  HTTP2
//
//  RFC 9113 §8.3 — turning a decoded HPACK field list into an HTTPRequest. Request pseudo-headers
//  (:method, :scheme, :authority, :path) carry the control data and MUST precede the regular fields,
//  each appear at most once, and be drawn only from that set. Field names MUST be lowercase (§8.2.1)
//  and connection-specific fields are forbidden (§8.2.2). A violation makes the request "malformed",
//  handled as a stream error (RST_STREAM PROTOCOL_ERROR, §8.1.1).
//

internal import HPACK
internal import HTTPCore

/// Maps a decoded HPACK field list onto an ``HTTPRequest`` (RFC 9113 §8.3).
enum HTTP2RequestMapper {
    /// Connection-specific fields that MUST NOT appear in an HTTP/2 request (RFC 9113 §8.2.2).
    private static let forbiddenFields: Set<String> = [
        "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade"
    ]

    /// Builds an ``HTTPRequest`` from `fields`, validating the §8.3 / §8.2 rules for `streamID`, and
    /// surfaces the Extended CONNECT `:protocol` (RFC 8441 §4) when present.
    static func makeRequest(
        from fields: [HPACKField],
        streamID: HTTP2StreamID
    ) throws(HTTP2Error) -> (request: HTTPRequest, connectProtocol: String?) {
        var method: String?
        var scheme: String?
        var authority: String?
        var path: String?
        var connectProtocol: String?
        var headerFields = HTTPFields()
        var sawRegularField = false

        // `fields` arrives already bounded: the HPACK/QPACK decoder enforces `maxFieldCount`,
        // `maxHeaderListSize`, and `maxFieldSize` at decode time (the single chokepoint), so the
        // field-count / header-list exhaustion vectors are stopped upstream and not re-checked here.
        for field in fields {
            if field.name.hasPrefix(":") {
                guard !sawRegularField else {
                    throw malformed(streamID, "pseudo-header after a regular field")
                }
                try assignPseudo(
                    field,
                    method: &method,
                    scheme: &scheme,
                    authority: &authority,
                    path: &path,
                    connectProtocol: &connectProtocol,
                    streamID: streamID
                )
            }
            else {
                sawRegularField = true
                try appendRegular(field, to: &headerFields, streamID: streamID)
            }
        }

        guard let method else {
            throw malformed(streamID, "missing :method")
        }
        guard let parsedMethod = HTTPMethod(rawValue: method) else {
            throw malformed(streamID, "invalid :method token")
        }

        // CONNECT has two shapes. Standard CONNECT (RFC 9113 §8.5) carries ONLY :authority and MUST
        // omit :scheme and :path — the target is the tunnel authority, so there is no path. Extended
        // CONNECT (RFC 8441 §4, identified by :protocol) is a normal request that carries :scheme and
        // :path like any other method.
        if parsedMethod == .connect, connectProtocol == nil {
            guard authority != nil else {
                throw malformed(streamID, "CONNECT requires :authority")
            }
            guard scheme == nil, path == nil else {
                throw malformed(streamID, "CONNECT must omit :scheme and :path")
            }
        }
        else {
            guard scheme != nil, let path, !path.isEmpty else {
                throw malformed(streamID, "missing or empty :scheme or :path")
            }
        }
        // `:protocol` is only valid on a CONNECT request (RFC 8441 §4).
        if connectProtocol != nil, parsedMethod != .connect {
            throw malformed(streamID, ":protocol is only valid on a CONNECT request")
        }
        let request = HTTPRequest(
            method: parsedMethod,
            scheme: scheme,
            authority: authority,
            path: path ?? "",
            headerFields: headerFields
        )
        return (request, connectProtocol)
    }

    /// Assigns one request pseudo-header, rejecting duplicates and unknown names (RFC 9113 §8.3).
    private static func assignPseudo(
        _ field: HPACKField,
        method: inout String?,
        scheme: inout String?,
        authority: inout String?,
        path: inout String?,
        connectProtocol: inout String?,
        streamID: HTTP2StreamID
    ) throws(HTTP2Error) {
        switch field.name {
            // `:method` is token-validated downstream by `HTTPMethod(rawValue:)`, which rejects controls.
            case ":method":
                try setOnce(&method, to: field.value, named: ":method", streamID)
            case ":scheme":
                try rejectControls(in: field.value, named: ":scheme", streamID)
                try setOnce(&scheme, to: field.value, named: ":scheme", streamID)
            case ":authority":
                try rejectControls(in: field.value, named: ":authority", streamID)
                try setOnce(&authority, to: field.value, named: ":authority", streamID)
            case ":path":
                try rejectControls(in: field.value, named: ":path", streamID)
                try setOnce(&path, to: field.value, named: ":path", streamID)
            case ":protocol":
                try rejectControls(in: field.value, named: ":protocol", streamID)
                try setOnce(&connectProtocol, to: field.value, named: ":protocol", streamID)
            default:
                throw malformed(streamID, "unknown request pseudo-header \(field.name)")
        }
    }

    /// Rejects a pseudo-header value carrying a control, SP, or DEL octet — the bytes that enable
    /// header / log injection and response splitting (RFC 9113 §8.3.1; CWE-113 / CWE-117).
    ///
    /// HPACK literal values are decoded as raw UTF-8 and can contain CR/LF/NUL, so — unlike the
    /// HTTP/1.1 target, validated at parse time — h2 pseudo-headers must be screened here before they
    /// reach `HTTPRequest`, the access log, or any reflecting handler.
    private static func rejectControls(
        in value: String,
        named name: String,
        _ streamID: HTTP2StreamID
    ) throws(HTTP2Error) {
        guard FieldValidation.isRequestTargetValue(value.utf8) else {
            throw malformed(streamID, "control byte in \(name)")
        }
    }

    private static func setOnce(
        _ slot: inout String?,
        to value: String,
        named name: String,
        _ streamID: HTTP2StreamID
    ) throws(HTTP2Error) {
        guard slot == nil else { throw malformed(streamID, "duplicate \(name)") }
        slot = value
    }

    /// Validates a regular field (§8.2.1 lowercase, §8.2.2 forbidden fields) and stores it.
    private static func appendRegular(
        _ field: HPACKField,
        to headerFields: inout HTTPFields,
        streamID: HTTP2StreamID
    ) throws(HTTP2Error) {
        guard !field.name.utf8.contains(where: { $0 >= 0x41 && $0 <= 0x5A }) else {
            throw malformed(streamID, "uppercase field name \(field.name)")
        }
        if field.name == "te", field.value != "trailers" {
            throw malformed(streamID, "TE may only be 'trailers'")
        }
        guard !forbiddenFields.contains(field.name) else {
            throw malformed(streamID, "connection-specific field \(field.name)")
        }
        guard let name = HTTPFieldName(field.name) else {
            throw malformed(streamID, "invalid field name \(field.name)")
        }
        guard headerFields.append(field.value, for: name) else {
            throw malformed(streamID, "invalid field value")
        }
    }

    private static func malformed(_ streamID: HTTP2StreamID, _ reason: String) -> HTTP2Error {
        .stream(streamID, .protocolError, reason)
    }
}
