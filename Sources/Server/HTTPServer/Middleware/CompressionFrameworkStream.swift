//
//  CompressionFrameworkStream.swift
//  HTTPServer
//
//  Darwin `Compression`'s `compression_stream` as an incremental encoder — the shared backend behind
//  the streaming `gzip` (RFC 1952) and `br` (RFC 7932) codings. `compression_encode_buffer`, which the
//  one-shot encoders use, has no resumable form; `compression_stream_init`/`_process`/`_destroy` is the
//  same codec driven octet-range by octet-range.
//
//  Byte-identity with the one-shot encoder is the property the middleware depends on, and it holds
//  because these encoders buffer internally and emit only at `COMPRESSION_STREAM_FINALIZE` — chunk
//  boundaries do not reach the output. Verified for `COMPRESSION_ZLIB` and `COMPRESSION_BROTLI` at
//  5 MB across 64 B / 4 KiB / 64 KiB / ~1 MB feeds; `COMPRESSION_LZFSE`, by contrast, *does* differ
//  under chunking, which is why the property is pinned by `ContentEncoderStreamTests` rather than
//  assumed for every algorithm.
//
//  The class owns two heap allocations (the stream state and one output window) and frees both exactly
//  once — at `finish`, or in `deinit` when a client disconnects mid-body and the producer is cancelled.
//

#if canImport(Compression)

    internal import Compression

    /// An incremental `Compression`-framework encode: one stream state plus one reused output window.
    final class CompressionFrameworkStream {
        /// The output window, in octets.
        ///
        /// Sized so a typical body chunk drains in one or two passes without reserving per-response
        /// memory that scales with the body.
        private static let windowSize = 16 * 1_024

        private let state: UnsafeMutablePointer<compression_stream>
        private let window: UnsafeMutablePointer<UInt8>

        /// Whether ``state`` still needs `compression_stream_destroy` — false once finalized.
        private var live: Bool

        /// Starts an encode with `algorithm`, or nil when the framework will not encode with it.
        init?(_ algorithm: compression_algorithm) {
            let state = UnsafeMutablePointer<compression_stream>.allocate(capacity: 1)
            guard
                compression_stream_init(state, COMPRESSION_STREAM_ENCODE, algorithm)
                    == COMPRESSION_STATUS_OK
            else {
                state.deallocate()
                return nil
            }
            self.state = state
            window = UnsafeMutablePointer<UInt8>.allocate(capacity: Self.windowSize)
            live = true
        }

        deinit {
            // Reached on cancellation: a disconnected client leaves `finish` uncalled, and the codec's
            // own allocation would otherwise outlive the response that owned it.
            if live {
                compression_stream_destroy(state)
            }
            state.deallocate()
            window.deallocate()
        }

        /// Codes `input`, finalizing the stream when `finalize` is set, and returns the octets produced.
        func process(_ input: [UInt8], finalize: Bool) throws(ContentEncodingError) -> [UInt8] {
            guard live else {
                throw .streamFinished
            }
            var coded: [UInt8] = []
            var pumped = false
            input.withUnsafeBufferPointer { source in
                // `src_ptr` must be a valid pointer even at size zero, which an empty array's
                // `baseAddress` is not; the window doubles as the never-read stand-in.
                state.pointee.src_ptr = source.baseAddress ?? UnsafePointer(window)
                state.pointee.src_size = source.count
                pumped = pump(finalize: finalize, into: &coded)
            }
            if finalize {
                compression_stream_destroy(state)
                live = false
            }
            guard pumped else {
                throw .encoderFailed
            }
            return coded
        }

        /// Drains the codec into `coded` until the input is consumed (or the stream ends); false on a
        /// backend error.
        private func pump(finalize: Bool, into coded: inout [UInt8]) -> Bool {
            let flags = finalize ? Int32(COMPRESSION_STREAM_FINALIZE.rawValue) : 0
            while true {
                state.pointee.dst_ptr = window
                state.pointee.dst_size = Self.windowSize
                let status = compression_stream_process(state, flags)
                guard status != COMPRESSION_STATUS_ERROR else {
                    return false
                }
                coded.append(
                    contentsOf: UnsafeBufferPointer(
                        start: window, count: Self.windowSize - state.pointee.dst_size
                    )
                )
                if status == COMPRESSION_STATUS_END {
                    return true
                }
                // Without FINALIZE the codec keeps the rest in its own window; stop when it has taken
                // everything we offered, or the loop would spin producing nothing.
                if !finalize, state.pointee.src_size == 0 {
                    return true
                }
            }
        }
    }

#endif
