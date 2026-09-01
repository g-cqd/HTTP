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
    /// The part-count, part-header and retained-byte bounds applied to every body decoded.
    public var limits: MultipartLimits

    /// Creates the decoder, enforcing `limits` on each body it decodes.
    public init(limits: MultipartLimits = .default) {
        self.limits = limits
    }

    /// Parses the body using the boundary from `contentType`; throws ``BodyDecodingError`` when the
    /// content type has no boundary (`unsupportedContentType`) or the body does not parse (`malformed`).
    ///
    /// A body that breaches ``limits`` is reported as `malformed`: the parse yielded no usable form,
    /// and a distinct case would tell a prober which bound they found.
    public func decode(_ body: [UInt8], contentType: String?) throws -> MultipartFormData {
        guard let contentType,
            let boundary = MultipartFormData.boundary(ofContentType: contentType)
        else {
            throw BodyDecodingError.unsupportedContentType
        }
        guard let form = MultipartFormData.parse(body, boundary: boundary, limits: limits) else {
            throw BodyDecodingError.malformed
        }
        return form
    }
}
