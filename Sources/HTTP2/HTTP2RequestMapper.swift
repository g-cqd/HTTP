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
        "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade",
    ]

    /// Builds an ``HTTPRequest`` from `fields`, validating the §8.3 / §8.2 rules for `streamID`.
    static func makeRequest(
        from fields: [HPACKField],
        streamID: HTTP2StreamID
    ) throws(HTTP2Error) -> HTTPRequest {
        var method: String?
        var scheme: String?
        var authority: String?
        var path: String?
        var headerFields = HTTPFields()
        var sawRegularField = false

        for field in fields {
            if field.name.hasPrefix(":") {
                guard !sawRegularField else {
                    throw malformed(streamID, "pseudo-header after a regular field")
                }
                try assignPseudo(
                    field, method: &method, scheme: &scheme, authority: &authority,
                    path: &path, streamID: streamID)
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
        return HTTPRequest(
            method: parsedMethod, scheme: scheme, authority: authority, path: path,
            headerFields: headerFields)
    }

    /// Assigns one request pseudo-header, rejecting duplicates and unknown names (RFC 9113 §8.3).
    private static func assignPseudo(
        _ field: HPACKField,
        method: inout String?,
        scheme: inout String?,
        authority: inout String?,
        path: inout String?,
        streamID: HTTP2StreamID
    ) throws(HTTP2Error) {
        switch field.name {
        case ":method": try setOnce(&method, to: field.value, named: ":method", streamID)
        case ":scheme": try setOnce(&scheme, to: field.value, named: ":scheme", streamID)
        case ":authority": try setOnce(&authority, to: field.value, named: ":authority", streamID)
        case ":path": try setOnce(&path, to: field.value, named: ":path", streamID)
        default: throw malformed(streamID, "unknown request pseudo-header \(field.name)")
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
