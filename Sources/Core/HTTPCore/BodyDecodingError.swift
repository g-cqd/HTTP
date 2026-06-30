//
//  BodyDecodingError.swift
//  HTTPCore
//
//  The error the shipped ``BodyDecoder`` conformers throw (Phase 2.3): the content type is not one the
//  decoder handles, or the body is malformed. A custom decoder may throw its own error type instead.
//

/// Why a ``BodyDecoder`` could not decode a body.
public enum BodyDecodingError: Error, Equatable, Sendable {
    /// The request's `Content-Type` is absent or not the one this decoder handles (e.g. a multipart body
    /// without a boundary parameter).
    case unsupportedContentType
    /// The body did not parse as the expected format.
    case malformed
}
