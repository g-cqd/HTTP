//
//  BrotliEncoder.swift
//  HTTPServer
//
//  The `br` content coding (RFC 7932) as a ``ContentEncoder`` — Darwin Compression's level-2 encoder, or
//  the Linux `libbrotlienc` shim (`CBrotli`); `nil` on a build with neither backend (Phase 3.3).
//

/// The `br` (Brotli) content coding (RFC 7932).
public struct BrotliEncoder: ContentEncoder {
    /// The `br` content-coding token (RFC 9110 §8.4.1).
    public let token = "br"

    /// Creates the encoder.
    public init() {
        // Stateless.
    }

    /// Encodes `body` as a Brotli stream, or `nil` on a build with no Brotli backend.
    public func encode(_ body: [UInt8]) -> [UInt8]? {
        #if canImport(Compression) || canImport(CBrotli)
            return Brotli.compress(body)
        #else
            return nil
        #endif
    }
}
