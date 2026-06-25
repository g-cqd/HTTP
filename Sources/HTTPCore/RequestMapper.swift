//
//  RequestMapper.swift
//  HTTPCore
//
//  RFC 9113 §8.3 / RFC 9114 §4.3 — turning a decoded header-field list (HPACK for HTTP/2, QPACK for
//  HTTP/3) into an ``HTTPRequest``. The two protocols share these rules verbatim: the request
//  pseudo-headers (:method, :scheme, :authority, :path) carry the control data and MUST precede the
//  regular fields, each appear at most once, and be drawn only from that set; field names MUST be
//  lowercase (§8.2.1 / §4.2); and connection-specific fields are forbidden (§8.2.2 / §4.2). The only
//  per-protocol difference is the error a violation maps to, so the engine passes a `malformed`
//  factory and this stays the single source of truth for both. Iterative; no recursion.
//

/// Maps a decoded header-field list onto an ``HTTPRequest`` (RFC 9113 §8.3 / RFC 9114 §4.3), shared by
/// the HTTP/2 and HTTP/3 engines so the §8.2/§4.2 validation lives in exactly one place.
public enum RequestMapper {
    /// Connection-specific fields forbidden in an HTTP/2 or HTTP/3 request (RFC 9113 §8.2.2 / 9114 §4.2).
    private static let forbiddenFields: Set<String> = [
        "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade"
    ]

    /// Builds an ``HTTPRequest`` from `fields`, validating the shared §8.3/§4.3 + §8.2/§4.2 rules, and
    /// surfaces an Extended CONNECT `:protocol` (RFC 8441 / RFC 9220) when present.
    ///
    /// A violation throws `malformed(reason)`: the caller bakes in the stream scope and the protocol's
    /// own malformed-request code (HTTP/2 PROTOCOL_ERROR / HTTP/3 H3_MESSAGE_ERROR), so this logic is
    /// identical for both engines.
    public static func makeRequest<E: Error>(
        from fields: [HeaderField],
        malformed: (String) -> E
    ) throws(E) -> (request: HTTPRequest, connectProtocol: String?) {
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
                    throw malformed("pseudo-header after a regular field")
                }
                try assignPseudo(
                    field,
                    method: &method,
                    scheme: &scheme,
                    authority: &authority,
                    path: &path,
                    connectProtocol: &connectProtocol,
                    malformed: malformed
                )
            }
            else {
                sawRegularField = true
                try appendRegular(field, to: &headerFields, malformed: malformed)
            }
        }

        guard let method else {
            throw malformed("missing :method")
        }
        guard let parsedMethod = HTTPMethod(rawValue: method) else {
            throw malformed("invalid :method token")
        }

        // CONNECT has two shapes. Standard CONNECT (RFC 9113 §8.5 / RFC 9114 §4.4) carries ONLY
        // :authority and MUST omit :scheme and :path — the target is the tunnel authority. Extended
        // CONNECT (RFC 8441 §4 / RFC 9220, :protocol present) is a normal request carrying :scheme/:path.
        if parsedMethod == .connect, connectProtocol == nil {
            guard authority != nil else {
                throw malformed("CONNECT requires :authority")
            }
            guard scheme == nil, path == nil else {
                throw malformed("CONNECT must omit :scheme and :path")
            }
        }
        else {
            guard scheme != nil, let path, !path.isEmpty else {
                throw malformed("missing or empty :scheme or :path")
            }
        }
        // `:protocol` is only valid on a CONNECT request (RFC 8441 §4 / RFC 9220).
        if connectProtocol != nil, parsedMethod != .connect {
            throw malformed(":protocol is only valid on a CONNECT request")
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

    /// Assigns one request pseudo-header, rejecting duplicates and unknown names (§8.3 / §4.3.1).
    private static func assignPseudo<E: Error>(
        _ field: HeaderField,
        method: inout String?,
        scheme: inout String?,
        authority: inout String?,
        path: inout String?,
        connectProtocol: inout String?,
        malformed: (String) -> E
    ) throws(E) {
        switch field.name {
            // `:method` is token-validated downstream by `HTTPMethod(rawValue:)`, which rejects controls.
            case ":method":
                try setOnce(&method, to: field.value, named: ":method", malformed)
            case ":scheme":
                try rejectControls(in: field.value, named: ":scheme", malformed)
                try setOnce(&scheme, to: field.value, named: ":scheme", malformed)
            case ":authority":
                try rejectControls(in: field.value, named: ":authority", malformed)
                try setOnce(&authority, to: field.value, named: ":authority", malformed)
            case ":path":
                try rejectControls(in: field.value, named: ":path", malformed)
                try setOnce(&path, to: field.value, named: ":path", malformed)
            case ":protocol":
                try rejectControls(in: field.value, named: ":protocol", malformed)
                try setOnce(&connectProtocol, to: field.value, named: ":protocol", malformed)
            default:
                throw malformed("unknown request pseudo-header \(field.name)")
        }
    }

    /// Rejects a pseudo-header value carrying a control, SP, or DEL octet — the bytes that enable header
    /// / log injection and response splitting (RFC 9113 §8.3.1 / RFC 9114 §4.3.1; CWE-113 / CWE-117).
    ///
    /// HPACK/QPACK literal values are decoded as raw UTF-8 and can contain CR/LF/NUL, so — unlike the
    /// HTTP/1.1 target validated at parse time — they must be screened here before reaching
    /// `HTTPRequest`, the access log, or any reflecting handler.
    private static func rejectControls<E: Error>(
        in value: String,
        named name: String,
        _ malformed: (String) -> E
    ) throws(E) {
        guard FieldValidation.isRequestTargetValue(value.utf8) else {
            throw malformed("control byte in \(name)")
        }
    }

    private static func setOnce<E: Error>(
        _ slot: inout String?,
        to value: String,
        named name: String,
        _ malformed: (String) -> E
    ) throws(E) {
        guard slot == nil else { throw malformed("duplicate \(name)") }
        slot = value
    }

    /// Validates a regular field (lowercase §8.2.1/§4.2, forbidden fields §8.2.2/§4.2, TE) and stores it.
    private static func appendRegular<E: Error>(
        _ field: HeaderField,
        to headerFields: inout HTTPFields,
        malformed: (String) -> E
    ) throws(E) {
        guard !field.name.utf8.contains(where: { $0 >= 0x41 && $0 <= 0x5A }) else {
            throw malformed("uppercase field name \(field.name)")
        }
        if field.name == "te", field.value != "trailers" {
            throw malformed("TE may only be 'trailers'")
        }
        guard !forbiddenFields.contains(field.name) else {
            throw malformed("connection-specific field \(field.name)")
        }
        guard let name = HTTPFieldName(field.name) else {
            throw malformed("invalid field name \(field.name)")
        }
        guard headerFields.append(field.value, for: name) else {
            throw malformed("invalid field value")
        }
    }
}
