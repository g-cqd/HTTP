//
//  MultipartFormDecoder.swift
//  HTTPCore
//
//  A ``BodyDecoder`` for `multipart/form-data` bodies (RFC 7578, Phase 2.3): reads the boundary from the
//  request's `Content-Type` and parses the parts into ``MultipartFormData``. Throws ``BodyDecodingError``
//  when the content type carries no boundary or the body is malformed.
//

/// Decodes a `multipart/form-data` body (RFC 7578) into ``MultipartFormData``.
public struct MultipartFormDecoder: BodyDecoder {
    /// Creates the decoder.
    public init() {
        // Stateless.
    }

    /// Parses the body using the boundary from `contentType`; throws ``BodyDecodingError`` when the
    /// content type has no boundary (`unsupportedContentType`) or the body does not parse (`malformed`).
    public func decode(_ body: [UInt8], contentType: String?) throws -> MultipartFormData {
        guard let contentType,
            let boundary = MultipartFormData.boundary(ofContentType: contentType)
        else {
            throw BodyDecodingError.unsupportedContentType
        }
        guard let form = MultipartFormData.parse(body, boundary: boundary) else {
            throw BodyDecodingError.malformed
        }
        return form
    }
}
