//
//  GzipEncoder.swift
//  HTTPServer
//
//  The `gzip` content coding (RFC 1952) as a ``ContentEncoder`` — Darwin Compression, or the Linux zlib
//  shim (`CZlibCoding`); `nil` on a build with neither backend (Phase 3.3).
//

/// The `gzip` content coding (RFC 1952).
public struct GzipEncoder: StreamingContentEncoder {
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

    /// An incremental gzip member on Darwin, nil elsewhere.
    ///
    /// The Linux backend is the `CZlibCoding` shim, whose only entry point is a one-shot
    /// `czlib_gzip_compress` over a worst-case-bounded destination — there is no resumable form to
    /// call, and zlib's own `deflate`/`deflateEnd` are not exposed through it. A streamed response
    /// therefore goes out **uncoded** on Linux rather than being buffered whole to code it.
    public func makeStream() -> (any ContentEncoderStream)? {
        #if canImport(Compression)
            return GzipEncoderStream()
        #else
            return nil
        #endif
    }
}
