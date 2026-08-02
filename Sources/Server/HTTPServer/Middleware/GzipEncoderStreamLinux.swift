//
//  GzipEncoderStreamLinux.swift
//  HTTPServer
//
//  The incremental `gzip` content coding (RFC 1952) for the non-Apple (Linux) build — the streaming
//  counterpart of ``Gzip/compress(_:)`` there, as GzipEncoderStream.swift is on Darwin. Compiled only
//  where the `CZlibCoding` shim is present (`#if canImport(CZlibCoding)`, i.e. the Linux graph, where
//  GzipEncoderStream.swift's `#if canImport(Compression)` compiles to nothing), so the two never
//  co-exist — the Gzip.swift / GzipLinux.swift split, one layer up.
//
//  Unlike the Darwin twin there is no envelope to maintain here. That one frames a *raw* DEFLATE stream
//  by hand: it emits ``Gzip/header``, folds the CRC-32 and the wrapping ISIZE as the octets go past, and
//  appends them itself, because Apple's `COMPRESSION_ZLIB` produces no gzip member. zlib's windowBits 31
//  produces the whole member — header, DEFLATE, CRC-32, ISIZE — so this is ``ZlibDeflateStream`` with
//  nothing added, and it inherits byte-identity with ``Gzip/compress(_:)`` from sharing that codec's one
//  initialization site rather than from re-deriving the trailer the same way twice.
//

#if canImport(CZlibCoding)

    /// An incremental gzip member (RFC 1952) over the system zlib's resumable `deflate`.
    final class GzipEncoderStream: ContentEncoderStream {
        private let deflate: ZlibDeflateStream

        /// Starts a gzip member, or nil when zlib will not start one.
        init?() {
            guard let deflate = ZlibDeflateStream(level: Gzip.level) else {
                return nil
            }
            self.deflate = deflate
        }

        deinit {
            // The codec state is the `ZlibDeflateStream`'s to free; ARC releases it here.
        }

        func update(_ input: [UInt8]) throws(ContentEncodingError) -> [UInt8] {
            try deflate.process(input, finalize: false)
        }

        func finish() throws(ContentEncodingError) -> [UInt8] {
            try deflate.process([], finalize: true)
        }
    }

#endif
