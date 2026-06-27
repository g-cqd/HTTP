//
//  Zstd.swift
//  HTTPServer
//
//  RFC 8878 — the `zstd` content coding via the system libzstd (the `CZstd` shim). Apple's
//  Compression framework has no Zstandard codec, so this is the only coding here not backed by
//  Darwin Compression; the whole file compiles only when the opt-in `CZstd` target is in the graph
//  (`HTTP_ZSTD`). The `zstd` content coding is a single raw zstd frame (RFC 8878 §3) with no extra
//  envelope — like Brotli's `br`, so this is the one-shot encoder with a worst-case-sized
//  destination. OUTBOUND only.
//

#if canImport(CZstd)

    internal import CZstd

    /// Produces a `zstd` content-coding body (RFC 8878) with the system libzstd one-shot encoder.
    enum Zstd {
        /// The compression level: 9 is a strong ratio for on-the-fly text at a still-modest cost
        /// (clamped to the library maximum). zstd's default is 3; 9 trades a little CPU for a
        /// smaller wire size.
        private static let level: Int32 = 9

        /// Compresses `input` into a single zstd frame, or `nil` if it is empty or libzstd could
        /// not encode it (the shim returns 0 on any `ZSTD_isError`, e.g. the frame not fitting the
        /// worst-case bound).
        static func compress(_ input: [UInt8]) -> [UInt8]? {
            guard !input.isEmpty else {
                return nil
            }
            let capacity = czstd_compress_bound(input.count)
            guard capacity > 0 else {
                return nil  // input above zstd's maximum — no worst-case bound exists
            }
            let clamped = min(level, Int32(czstd_max_level()))
            var destination = [UInt8](repeating: 0, count: capacity)
            let written = input.withUnsafeBufferPointer { source in
                destination.withUnsafeMutableBufferPointer { destination -> Int in
                    guard let source = source.baseAddress, let destination = destination.baseAddress
                    else {
                        return 0
                    }
                    return czstd_compress(destination, capacity, source, input.count, clamped)
                }
            }
            guard written > 0 else {
                return nil
            }
            destination.removeLast(destination.count - written)
            return destination
        }
    }

#endif
