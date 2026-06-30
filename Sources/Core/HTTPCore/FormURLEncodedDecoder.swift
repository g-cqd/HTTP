//
//  FormURLEncodedDecoder.swift
//  HTTPCore
//
//  A ``BodyDecoder`` for `application/x-www-form-urlencoded` bodies (Phase 2.3): decodes to
//  ``QueryParameters`` (the same encoding as the query component). Lenient — a malformed escape stays
//  literal — so it never throws.
//

/// Decodes an `application/x-www-form-urlencoded` body into ``QueryParameters``.
public struct FormURLEncodedDecoder: BodyDecoder {
    /// Creates the decoder.
    public init() {
        // Stateless.
    }

    /// Parses the body as form fields; the content type is ignored (the format is unambiguous).
    public func decode(_ body: [UInt8], contentType _: String?) -> QueryParameters {
        QueryParameters.parse(form: String(decoding: body, as: Unicode.UTF8.self))
    }
}
