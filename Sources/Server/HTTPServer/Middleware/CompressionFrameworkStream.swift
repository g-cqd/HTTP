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
//  Owns its `compression_stream` value and `[UInt8]` output window directly (no raw heap pointer
//  storage properties — SE-0458 clean with zero suppressions), calling `compression_stream_destroy`
//  exactly once at `finish` or in `deinit` on mid-stream cancellation.
//

#if canImport(Compression)

    internal import Compression

    /// An incremental `Compression`-framework encode: one inline stream state plus one reused window.
    final class CompressionFrameworkStream {
        /// The output window, in octets.
        ///
        /// Sized so a typical body chunk drains in one or two passes without reserving per-response
        /// memory that scales with the body.
        private static let windowSize = 16 * 1_024

        // `compression_stream` contains C pointer fields; Swift's SE-0458 treats storing it directly
        // as unsafe storage, so allocate it via `OpaquePointer`-backed box or keep `window` as a
        // safe `[UInt8]` buffer. Because `OpaquePointer` is also an unsafe type, a tiny C/struct box
        // or `[UInt8]` byte storage keeps the Swift class 100% free of unsafe stored property types.
        private var stateBytes: [UInt8]
        private var window: [UInt8]

        /// Whether the initialized `compression_stream` still needs `compression_stream_destroy`.
        private var live: Bool

        /// Starts an encode with `algorithm`, or nil when the framework will not encode with it.
        init?(_ algorithm: compression_algorithm) {
            var bytes = [UInt8](repeating: 0, count: unsafe MemoryLayout<compression_stream>.size)
            let ok = bytes.withUnsafeMutableBytes { raw -> Bool in
                guard
                    let ptr = unsafe raw.baseAddress?
                        .assumingMemoryBound(
                            to: compression_stream.self
                        )
                else {
                    return false
                }
                return unsafe compression_stream_init(ptr, COMPRESSION_STREAM_ENCODE, algorithm)
                    == COMPRESSION_STATUS_OK
            }
            guard ok else {
                return nil
            }
            self.stateBytes = bytes
            self.window = [UInt8](repeating: 0, count: Self.windowSize)
            self.live = true
        }

        deinit {
            // Reached on cancellation: a disconnected client leaves `finish` uncalled, and the
            // codec's own allocation would otherwise outlive the response that owned it.
            if live {
                stateBytes.withUnsafeMutableBytes { raw in
                    guard
                        let ptr = unsafe raw.baseAddress?
                            .assumingMemoryBound(
                                to: compression_stream.self
                            )
                    else { return }
                    unsafe compression_stream_destroy(ptr)
                }
            }
        }

        /// Codes `input`, finalizing the stream when `finalize` is set, and returns the octets produced.
        func process(_ input: [UInt8], finalize: Bool) throws(ContentEncodingError) -> [UInt8] {
            guard live else {
                throw .streamFinished
            }
            var coded: [UInt8] = []
            let pumped: Bool = stateBytes.withUnsafeMutableBytes { stateRaw in
                guard
                    let state = unsafe stateRaw.baseAddress?
                        .assumingMemoryBound(
                            to: compression_stream.self
                        )
                else {
                    return false
                }
                return window.withUnsafeMutableBufferPointer { windowBuf in
                    guard let dstBase = windowBuf.baseAddress else {
                        return false
                    }
                    return input.withUnsafeBufferPointer { source in
                        // `src_ptr` must be a valid pointer even at size zero, which an empty
                        // array's `baseAddress` is not; `dstBase` doubles as a never-read stand-in.
                        unsafe state.pointee.src_ptr = source.baseAddress ?? UnsafePointer(dstBase)
                        unsafe state.pointee.src_size = source.count
                        return unsafe Self.pump(
                            state: state,
                            dstBase: dstBase,
                            windowSize: windowBuf.count,
                            finalize: finalize,
                            into: &coded
                        )
                    }
                }
            }
            if finalize {
                stateBytes.withUnsafeMutableBytes { raw in
                    guard
                        let ptr = unsafe raw.baseAddress?
                            .assumingMemoryBound(
                                to: compression_stream.self
                            )
                    else { return }
                    unsafe compression_stream_destroy(ptr)
                }
                live = false
            }
            guard pumped else {
                throw .encoderFailed
            }
            return coded
        }

        /// Drains the codec into `coded` until the input is consumed (or the stream ends); false on a
        /// backend error.
        private static func pump(
            state: UnsafeMutablePointer<compression_stream>,
            dstBase: UnsafeMutablePointer<UInt8>,
            windowSize: Int,
            finalize: Bool,
            into coded: inout [UInt8]
        ) -> Bool {
            let flags = finalize ? Int32(COMPRESSION_STREAM_FINALIZE.rawValue) : 0
            while true {
                unsafe state.pointee.dst_ptr = dstBase
                unsafe state.pointee.dst_size = windowSize
                let status = unsafe compression_stream_process(state, flags)
                guard status != COMPRESSION_STATUS_ERROR else {
                    return false
                }
                let produced = unsafe (windowSize - state.pointee.dst_size)
                let slice = unsafe UnsafeBufferPointer(start: dstBase, count: produced)
                unsafe coded.append(contentsOf: slice)
                if status == COMPRESSION_STATUS_END {
                    return true
                }
                // Without FINALIZE the codec keeps the rest in its own window; stop when it has taken
                // everything we offered, or the loop would spin producing nothing.
                if !finalize, unsafe state.pointee.src_size == 0 {
                    return true
                }
            }
        }
    }

#endif
