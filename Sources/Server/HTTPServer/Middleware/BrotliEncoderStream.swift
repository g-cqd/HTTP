//
//  BrotliEncoderStream.swift
//  HTTPServer
//
//  The incremental `br` content coding (RFC 7932) — the streaming counterpart of ``Brotli/compress(_:)``.
//  Unlike gzip there is no envelope to maintain: the `br` coding *is* the raw Brotli stream, so this is
//  ``CompressionFrameworkStream`` with nothing added, and the type exists only to name that fact and to
//  give the coding its own conformance.
//

#if canImport(Compression)

    internal import Compression

    /// An incremental Brotli stream (RFC 7932) over Darwin's level-2 encoder.
    final class BrotliEncoderStream: ContentEncoderStream {
        private let encoder: CompressionFrameworkStream

        /// Starts a Brotli stream, or nil when the framework will not encode Brotli.
        init?() {
            guard let encoder = CompressionFrameworkStream(COMPRESSION_BROTLI) else {
                return nil
            }
            self.encoder = encoder
        }

        deinit {
            // The codec state is the `CompressionFrameworkStream`'s to free; ARC releases it here.
        }

        func update(_ input: [UInt8]) throws(ContentEncodingError) -> [UInt8] {
            try encoder.process(input, finalize: false)
        }

        func finish() throws(ContentEncodingError) -> [UInt8] {
            try encoder.process([], finalize: true)
        }
    }

#endif
