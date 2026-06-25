//
//  HTTP2RequestMapper.swift
//  HTTP2
//
//  RFC 9113 §8.3 — turning a decoded HPACK field list into an ``HTTPRequest``. The §8.3 / §8.2 rules
//  are shared verbatim with HTTP/3, so they live in the ``RequestMapper`` substrate (HTTPCore); this is
//  the thin HTTP/2 adapter that supplies the malformed-request error: a stream PROTOCOL_ERROR (§8.1.1).
//

internal import HPACK
internal import HTTPCore

/// Maps a decoded HPACK field list onto an ``HTTPRequest`` (RFC 9113 §8.3).
enum HTTP2RequestMapper {
    /// Builds an ``HTTPRequest`` from `fields` for `streamID`, surfacing the Extended CONNECT
    /// `:protocol` (RFC 8441 §4) when present; a malformed request is a stream PROTOCOL_ERROR (§8.1.1).
    static func makeRequest(
        from fields: [HPACKField],
        streamID: HTTP2StreamID
    ) throws(HTTP2Error) -> (request: HTTPRequest, connectProtocol: String?) {
        try RequestMapper.makeRequest(from: fields) { reason in
            HTTP2Error.stream(streamID, .protocolError, reason)
        }
    }
}
