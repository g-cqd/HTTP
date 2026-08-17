//
//  GzipEncoderStreamLinux.swift
//  HTTPServer
//
//  The incremental `gzip` content coding (RFC 1952) for the non-Apple (Linux) build — the streaming
//  counterpart of ``Gzip/compress(_:)`` there, as GzipEncoderStream.swift is on Darwin. Compiled
//  only where Apple's Compression framework is absent (`#if !canImport(Compression)`), so the two
//  never co-exist — the Gzip.swift / GzipLinux.swift split, one layer up.
//
//  Byte-identity with the buffered path is the property ``CompressionMiddleware`` depends on, and
//  it is structural here: ``Gzip/compress(_:)`` and this stream are the SAME ``GzipDeflator`` at
//  the same ``Gzip/level``, driven with different chunk sizes, and that codec's output under
//  no-flush pumping is a function of the input octets alone, never of the chunking — pinned by
//  `ContentEncoderStreamTests` on both platforms and by the codec's own chunk-stability suite.
//

#if !canImport(Compression)

    internal import HTTPDeflate

    /// An incremental gzip member (RFC 1952) over the in-house ``GzipDeflator``.
    final class GzipEncoderStream: ContentEncoderStream {
        private var encoder: GzipDeflator
        /// Whether ``finish()`` has sealed the member — further input is a caller defect.
        private var finished = false

        /// Starts a gzip member (never nil — the in-house codec has no failure mode; the zlib
        /// shim this replaced could fail on OOM).
        init?() {
            encoder = GzipDeflator(level: Gzip.level)
        }

        deinit {
            // The codec state is plain Swift storage; ARC releases it here — including on the
            // cancellation path, where a disconnected client leaves `finish` uncalled.
        }

        func update(_ input: [UInt8]) throws(ContentEncodingError) -> [UInt8] {
            guard !finished else {
                throw .streamFinished
            }
            var output: [UInt8] = []
            encoder.pump(input, appendingTo: &output)
            return output
        }

        func finish() throws(ContentEncodingError) -> [UInt8] {
            guard !finished else {
                throw .streamFinished
            }
            finished = true
            var output: [UInt8] = []
            encoder.pump([], appendingTo: &output, flush: .finish)
            return output
        }
    }

#endif
