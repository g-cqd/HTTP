//
//  FormURLEncodedDecoder.swift
//  HTTPCore
//
//  A ``BodyDecoder`` for `application/x-www-form-urlencoded` bodies (Phase 2.3) — the HTML form
//  encoding of RFC 1866 §8.2.1, maintained today by the WHATWG URL Standard §5, over the
//  percent-escaping of RFC 3986 §2.1. Decodes to ``QueryParameters`` (the same encoding as the query
//  component), delegating to its shared `parse(form:)`. Lenient — a malformed escape stays literal —
//  so it never throws.
//

/// Decodes an `application/x-www-form-urlencoded` body (RFC 1866 §8.2.1 / WHATWG URL §5) into
/// ``QueryParameters``.
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
