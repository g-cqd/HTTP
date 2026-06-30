//
//  ZstdEncoder.swift
//  HTTPServer
//
//  The `zstd` content coding (RFC 8878) as a ``ContentEncoder`` — the opt-in `CZstd` shim over the system
//  libzstd (`HTTP_ZSTD`); `nil` on a build without that shim (Phase 3.3).
//

/// The `zstd` content coding (RFC 8878).
public struct ZstdEncoder: ContentEncoder {
    /// The `zstd` content-coding token (RFC 9110 §8.4.1).
    public let token = "zstd"

    /// Creates the encoder.
    public init() {
        // Stateless.
    }

    /// Encodes `body` as a zstd frame, or `nil` on a build without the `CZstd` shim.
    public func encode(_ body: [UInt8]) -> [UInt8]? {
        #if canImport(CZstd)
            return Zstd.compress(body)
        #else
            return nil
        #endif
    }
}
