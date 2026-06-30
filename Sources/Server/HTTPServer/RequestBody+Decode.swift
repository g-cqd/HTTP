//
//  RequestBody+Decode.swift
//  HTTPServer
//
//  Phase 2.3 — decoding a request body into a typed value through the ``BodyDecoder`` seam: collect the
//  body, then hand it (with the request's content type) to the decoder. Plugs any decoder into a handler
//  — the shipped form / multipart ones, or a consumer's JSON `Decodable` codec.
//

public import HTTPCore

extension RequestBody {
    /// Collects the body and decodes it with `decoder`, passing the request's `Content-Type` for codecs
    /// that need it (e.g. multipart's boundary) — Phase 2.3.
    public func decode<D: BodyDecoder>(
        using decoder: D, for request: HTTPRequest
    ) async throws -> D.Value {
        try decoder.decode(await collect(), contentType: request.headerFields[.contentType])
    }
}
