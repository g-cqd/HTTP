//
//  CompressingBodyWriter.swift
//  HTTPServer
//
//  The ``ResponseBodyWriter`` that ``CompressionMiddleware`` interposes between a streamed response's
//  producer and the engine's real writer: each chunk is coded on its way past and only the coded octets
//  reach the wire. Nothing accumulates — the producer's chunk is coded and forwarded, and what the
//  codec keeps is its own fixed window, not a function of the body's length.
//
//  ## What it does with a `FileRegion`
//
//  It streams it through the compressor, which forfeits `sendfile(2)`. That is not a preference; by the
//  time `writeFile(_:)` is reached the response head — including `Content-Encoding` — is already on the
//  wire, so handing the descriptor to the kernel would put *identity* octets under a header that
//  promises a coding. The choice belongs upstream, where the head is still mutable, and it is made
//  there: ``CompressionMiddleware`` decides whether to code at all, and a response that already carries
//  `Content-Encoding` is left alone.
//
//  That last point is what preserves zero-copy where it pays. ``FileResponder``'s precompressed
//  sidecars (`.br` / `.gz`) set `Content-Encoding` themselves, so the middleware declines them and the
//  h1 writer's `sendfile(2)` path survives for exactly the large static assets it was built for. A
//  large file with *no* sidecar trades the kernel copy for the wire bytes — which for the compressible
//  media types this middleware admits is usually the better trade, and for the incompressible ones it
//  never gets asked, because those are excluded before the head is written.
//

/// Codes each chunk of a streamed response body on its way to the engine's writer (RFC 9110 §8.4.1).
struct CompressingBodyWriter: ResponseBodyWriter {
    /// The response's coding, owned for the life of the body.
    let coding: ContentCodingSession

    /// The engine's writer — the real backpressure point, unchanged by the interposition.
    let downstream: any ResponseBodyWriter

    /// Codes `chunk` and forwards whatever the codec produced, if anything.
    ///
    /// An empty result is normal, not an error: a backend still filling its window has nothing to emit
    /// yet, and forwarding an empty chunk would frame a zero-length chunk that RFC 9112 §7.1 reserves
    /// for the end of a chunked body.
    func write(_ chunk: [UInt8]) async throws {
        let coded = try coding.update(chunk)
        guard !coded.isEmpty else {
            return
        }
        try await downstream.write(coded)
    }

    /// Streams `region` through the compressor rather than through `sendfile(2)` — see the file note.
    func writeFile(_ region: FileRegion) async throws {
        try await FileRegionStreamer.stream(region, to: self)
    }

    /// Flushes the coding and writes its trailing octets (a gzip trailer, a final Brotli block).
    ///
    /// Must run exactly once, after the producer has finished, or the body on the wire is a coded
    /// stream that no decoder will accept as complete.
    func finish() async throws {
        let tail = try coding.finish()
        guard !tail.isEmpty else {
            return
        }
        try await downstream.write(tail)
    }
}
