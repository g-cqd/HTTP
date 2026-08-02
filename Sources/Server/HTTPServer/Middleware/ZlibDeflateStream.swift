//
//  ZlibDeflateStream.swift
//  HTTPServer
//
//  The system zlib's resumable `deflate` as an incremental encoder — the Linux counterpart of
//  ``CompressionFrameworkStream``, and the backend behind the streaming `gzip` coding (RFC 1952) there.
//  `czlib_gzip_compress`, which the buffered path uses, drives one `deflate(Z_FINISH)` over the whole
//  body; this drives the same codec, initialized by the same `czlib_deflate_begin`, octet-range by
//  octet-range through `czlib_deflate_stream_pump`.
//
//  Byte-identity with the buffered path is the property ``CompressionMiddleware`` depends on, and here
//  it is a property of zlib rather than a hope: the pump only ever flushes `Z_NO_FLUSH` until the final
//  `Z_FINISH`, and `deflate_slow` will not emit while its lookahead is short under `Z_NO_FLUSH`, so a
//  caller's chunk boundary cannot reach the output. `Z_SYNC_FLUSH` would have made the coding a function
//  of the chunking; the shim does not expose it. Pinned by `ContentEncoderStreamTests` on both platforms
//  rather than assumed, because it is an implementation property that a zlib bump could take away.
//
//  The class owns two heap allocations (the shim's stream state and one output window) and frees both
//  exactly once — at `finish`, or in `deinit` when a client disconnects mid-body and the producer is
//  cancelled.
//

#if canImport(CZlibCoding)

    internal import CZlibCoding

    /// An incremental zlib gzip encode: one shim-owned `z_stream` plus one reused output window.
    final class ZlibDeflateStream {
        /// The output window, in octets.
        ///
        /// The same 16 KiB ``CompressionFrameworkStream`` uses, so a typical body chunk drains in one or
        /// two passes on either platform without reserving per-response memory that scales with the body.
        private static let windowSize = 16 * 1_024

        private let state: OpaquePointer
        private let window: UnsafeMutablePointer<UInt8>

        /// Whether ``state`` still needs `czlib_deflate_stream_destroy` — false once finalized.
        private var live: Bool

        /// Starts a gzip member at `level`, or nil when zlib will not start one.
        init?(level: Int32) {
            guard let state = czlib_deflate_stream_create(level) else {
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
                czlib_deflate_stream_destroy(state)
            }
            window.deallocate()
        }

        /// Codes `input`, finalizing the member when `finalize` is set, and returns the octets produced.
        func process(_ input: [UInt8], finalize: Bool) throws(ContentEncodingError) -> [UInt8] {
            guard live else {
                throw .streamFinished
            }
            var coded: [UInt8] = []
            var pumped = false
            input.withUnsafeBufferPointer { source in
                pumped = pump(source, finalize: finalize, into: &coded)
            }
            if finalize {
                czlib_deflate_stream_destroy(state)
                live = false
            }
            guard pumped else {
                throw .encoderFailed
            }
            return coded
        }

        /// Drains the codec into `coded` until `source` is consumed (or the member ends); false on a
        /// zlib error.
        private func pump(
            _ source: UnsafeBufferPointer<UInt8>,
            finalize: Bool,
            into coded: inout [UInt8]
        ) -> Bool {
            var offset = 0
            while true {
                var consumed = 0
                var produced = 0
                var ended: Int32 = 0
                let taken = source.baseAddress.map { $0 + offset }
                let status = czlib_deflate_stream_pump(
                    state,
                    taken,
                    source.count - offset,
                    &consumed,
                    window,
                    Self.windowSize,
                    &produced,
                    finalize ? 1 : 0,
                    &ended
                )
                guard status == 1 else {
                    return false
                }
                offset += consumed
                coded.append(
                    contentsOf: UnsafeBufferPointer(start: window, count: produced)
                )
                if ended == 1 {
                    return true
                }
                // A full window means zlib had more to say than there was room for, so it must be asked
                // again — that, and not "is there input left", is zlib's own re-entry rule.
                if produced == Self.windowSize {
                    continue
                }
                // Room left in the window and not finalizing: `deflate` has taken everything offered and
                // will say nothing more until it is given more input.
                guard finalize else {
                    return true
                }
                // Finalizing, window unfilled, and still no `Z_STREAM_END`: zlib made no progress it can
                // make, so looping would spin. Report it instead of hanging the response body.
                guard consumed > 0 || produced > 0 else {
                    return false
                }
            }
        }
    }

#endif
