//
//  GzipEncoder.swift
//  HTTPServer
//
//  The `gzip` content coding (RFC 1952) as a ``ContentEncoder`` — Darwin Compression, or the Linux zlib
//  shim (`CZlibCoding`); `nil` on a build with neither backend (Phase 3.3).
//

/// The `gzip` content coding (RFC 1952).
public struct GzipEncoder: ContentEncoder {
    /// The `gzip` content-coding token (RFC 9110 §8.4.1).
    public let token = "gzip"

    /// Creates the encoder.
    public init() {
        // Stateless.
    }

    /// Encodes `body` as a gzip member, or `nil` on a build with no gzip backend.
    public func encode(_ body: [UInt8]) -> [UInt8]? {
        #if canImport(Compression) || canImport(CZlibCoding)
            return Gzip.compress(body)
        #else
            return nil
        #endif
    }
}
