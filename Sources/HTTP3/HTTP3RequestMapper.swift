//
//  HTTP3RequestMapper.swift
//  HTTP3
//
//  RFC 9114 §4.3 — turning a decoded QPACK field list into an ``HTTPRequest``, the HTTP/3 analog of the
//  HTTP/2 §8.3 mapping. The §4.3 / §4.2 rules are shared verbatim with HTTP/2, so they live in the
//  ``RequestMapper`` substrate (HTTPCore); this is the thin HTTP/3 adapter that supplies the
//  malformed-request error: a stream error of type H3_MESSAGE_ERROR (§4.1.2).
//

internal import HTTPCore

/// Maps a decoded QPACK field list onto an ``HTTPRequest`` (RFC 9114 §4.3).
enum HTTP3RequestMapper {
    /// Builds an ``HTTPRequest`` from `fields` for `streamID`, surfacing the Extended CONNECT
    /// `:protocol` (RFC 9220) when present; a malformed request is a stream H3_MESSAGE_ERROR (§4.1.2).
    static func makeRequest(
        from fields: [HeaderField],
        streamID: QUICStreamID
    ) throws(HTTP3Error) -> (request: HTTPRequest, connectProtocol: String?) {
        try RequestMapper.makeRequest(from: fields) { reason in
            HTTP3Error.stream(streamID, .h3MessageError, reason)
        }
    }
}
