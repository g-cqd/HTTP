//
//  ContentEncoder.swift
//  HTTPServer
//
//  The pluggable content-coding seam (Phase 3.3): a value that names a `Content-Encoding` token and
//  encodes a response body. ``CompressionMiddleware`` negotiates over a list of these (server-preference
//  order), so a consumer can add or replace codings — the built-in ``GzipEncoder`` / ``BrotliEncoder`` /
//  ``ZstdEncoder`` are just the default list, each abstracting its Darwin-vs-Linux backend behind one
//  `encode`.
//

/// A response-body content coding (RFC 9110 §8.4.1) — its token and a one-shot encoder.
public protocol ContentEncoder: Sendable {
    /// The `Content-Encoding` token this encoder produces (e.g. `gzip`, `br`, `zstd`).
    var token: String { get }

    /// Encodes `body`, or `nil` when it cannot on this platform / build (the response is then served
    /// unencoded).
    func encode(_ body: [UInt8]) -> [UInt8]?
}
