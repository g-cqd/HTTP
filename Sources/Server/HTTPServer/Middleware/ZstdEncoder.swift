//
//  ZstdEncoder.swift
//  HTTPServer
//
//  The `zstd` content coding (RFC 8878) as a ``ContentEncoder`` — the opt-in `CZstd` shim over the system
//  libzstd (`HTTP_ZSTD`); `nil` on a build without that shim (Phase 3.3).
//

/// The `zstd` content coding (RFC 8878).
///
/// Deliberately **not** a ``StreamingContentEncoder``. The `CZstd` shim bridges only libzstd's one-shot
/// `ZSTD_compress` over a worst-case-bounded destination; `ZSTD_compressStream2` and the `ZSTD_CCtx`
/// lifecycle it needs are not exposed. Rather than buffer a streamed body whole in order to code it —
/// the retention a streamed body exists to avoid — a streamed response that negotiates `zstd` is served
/// **uncoded**. Buffered responses are unaffected.
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
