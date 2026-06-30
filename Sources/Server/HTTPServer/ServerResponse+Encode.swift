//
//  ServerResponse+Encode.swift
//  HTTPServer
//
//  Phase 2.3 — building a response by encoding a typed value through the ``BodyEncoder`` seam: the
//  encoder supplies both the bytes and the `Content-Type`. Complements the ready-made byte / string
//  constructors (`.json(_:)` / `.text(_:)`) with a pluggable, typed encoder path.
//

public import HTTPCore

extension ServerResponse {
    /// A response that encodes `value` with `encoder`, carrying the encoder's `Content-Type` (Phase 2.3).
    public static func encoded<E: BodyEncoder>(
        _ value: E.Value, using encoder: E, status: HTTPStatus = .ok
    ) throws -> ServerResponse {
        var fields = HTTPFields()
        _ = fields.setValue(encoder.contentType, for: .contentType)
        return ServerResponse(
            HTTPResponse(status: status, headerFields: fields), body: try encoder.encode(value)
        )
    }
}
