//
//  HTTP3RequestMapper.swift
//  HTTP3
//
//  RFC 9114 §4.3 — turning a decoded QPACK field list into an HTTPRequest, the HTTP/3 analog of the
//  HTTP/2 §8.3 mapping. Request pseudo-headers (:method, :scheme, :authority, :path) carry the control
//  data and MUST precede the regular fields (§4.3.1), each appear at most once, and be drawn only from
//  that set. Field names MUST be lowercase (§4.2) and connection-specific fields are forbidden (§4.2).
//  A violation makes the request "malformed", handled as a stream error of type H3_MESSAGE_ERROR
//  (§4.1.2).
//

internal import HTTPCore

/// Maps a decoded QPACK field list onto an ``HTTPRequest`` (RFC 9114 §4.3).
enum HTTP3RequestMapper {

    /// Connection-specific fields that MUST NOT appear in an HTTP/3 request (RFC 9114 §4.2).
    private static let forbiddenFields: Set<String> = [
        "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade",
    ]

    /// Builds an ``HTTPRequest`` from `fields`, validating the §4.3 / §4.2 rules for `streamID`, and
    /// surfaces the Extended CONNECT `:protocol` (RFC 9220) when present.
    static func makeRequest(
        from fields: [HeaderField],
        streamID: QUICStreamID
    ) throws(HTTP3Error) -> (request: HTTPRequest, connectProtocol: String?) {
        var method: String?
        var scheme: String?
        var authority: String?
        var path: String?
        var connectProtocol: String?
        var headerFields = HTTPFields()
        var sawRegularField = false

        for field in fields {
            if field.name.hasPrefix(":") {
                guard !sawRegularField else {
                    throw malformed(streamID, "pseudo-header after a regular field")
                }
                try assignPseudo(
                    field, method: &method, scheme: &scheme, authority: &authority,
                    path: &path, connectProtocol: &connectProtocol, streamID: streamID)
            } else {
                sawRegularField = true
                try appendRegular(field, to: &headerFields, streamID: streamID)
            }
        }

        guard let method, let scheme, let path, !path.isEmpty else {
            throw malformed(streamID, "missing or empty :method, :scheme, or :path")
        }
        guard let parsedMethod = HTTPMethod(rawValue: method) else {
            throw malformed(streamID, "invalid :method token")
        }
        // `:protocol` is only valid on an Extended CONNECT request (RFC 9220 / RFC 8441 §4).
        if connectProtocol != nil, parsedMethod != .connect {
            throw malformed(streamID, ":protocol is only valid on a CONNECT request")
        }
        let request = HTTPRequest(
            method: parsedMethod, scheme: scheme, authority: authority, path: path,
            headerFields: headerFields)
        return (request, connectProtocol)
    }

    /// Assigns one request pseudo-header, rejecting duplicates and unknown names (RFC 9114 §4.3.1).
    private static func assignPseudo(
        _ field: HeaderField,
        method: inout String?,
        scheme: inout String?,
        authority: inout String?,
        path: inout String?,
        connectProtocol: inout String?,
        streamID: QUICStreamID
    ) throws(HTTP3Error) {
        switch field.name {
        case ":method": try setOnce(&method, to: field.value, named: ":method", streamID)
        case ":scheme": try setOnce(&scheme, to: field.value, named: ":scheme", streamID)
        case ":authority": try setOnce(&authority, to: field.value, named: ":authority", streamID)
        case ":path": try setOnce(&path, to: field.value, named: ":path", streamID)
        case ":protocol":
            try setOnce(&connectProtocol, to: field.value, named: ":protocol", streamID)
        default: throw malformed(streamID, "unknown request pseudo-header \(field.name)")
        }
    }

    private static func setOnce(
        _ slot: inout String?,
        to value: String,
        named name: String,
        _ streamID: QUICStreamID
    ) throws(HTTP3Error) {
        guard slot == nil else { throw malformed(streamID, "duplicate \(name)") }
        slot = value
    }

    /// Validates a regular field (§4.2 lowercase, §4.2 forbidden fields) and stores it.
    private static func appendRegular(
        _ field: HeaderField,
        to headerFields: inout HTTPFields,
        streamID: QUICStreamID
    ) throws(HTTP3Error) {
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

    private static func malformed(_ streamID: QUICStreamID, _ reason: String) -> HTTP3Error {
        .stream(streamID, .h3MessageError, reason)
    }
}
