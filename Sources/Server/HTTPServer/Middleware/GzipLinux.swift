//
//  GzipLinux.swift
//  HTTPServer
//
//  RFC 1952 gzip content coding for the non-Apple (Linux) build, via the one-shot `CZlibCoding` zlib shim
//  (`deflateInit2` windowBits 31 — zlib emits the full gzip header + CRC-32 + ISIZE). The counterpart to
//  Gzip.swift, which frames Darwin's raw-DEFLATE encoder by hand. Compiled only where the shim is present
//  (`#if canImport(CZlibCoding)`, i.e. the Linux graph; Gzip.swift is excluded there), with the same
//  `compress(_:)` shape so CompressionMiddleware dispatches uniformly across platforms.
//

#if canImport(CZlibCoding)

    internal import CZlibCoding

    /// Produces gzip members (RFC 1952) via the system zlib one-shot encoder (level 6 — zlib's default
    /// balance of ratio and speed for on-the-fly text).
    enum Gzip {
        private static let level: Int32 = 6

        /// Compresses `input` into a gzip member, or `nil` if it is empty or zlib could not encode it
        /// (the shim returns 0 on any zlib error, e.g. the output not fitting the worst-case bound).
        static func compress(_ input: [UInt8]) -> [UInt8]? {
            guard !input.isEmpty else {
                return nil
            }
            let capacity = czlib_compress_bound(input.count)
            guard capacity > 0 else {
                return nil
            }
            var destination = [UInt8](repeating: 0, count: capacity)
            let written = input.withUnsafeBufferPointer { source in
                destination.withUnsafeMutableBufferPointer { destination -> Int in
                    guard let source = source.baseAddress, let destination = destination.baseAddress
                    else {
                        return 0
                    }
                    return czlib_gzip_compress(destination, capacity, source, input.count, level)
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
