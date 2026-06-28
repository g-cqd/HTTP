//
//  BrotliLinux.swift
//  HTTPServer
//
//  RFC 7932 Brotli content coding — encode + decode — for the non-Apple (Linux) build, via the opt-in
//  CBrotli libbrotli shim. The counterpart to Brotli.swift (encode over Darwin Compression) and the
//  `br` arm of Inflate.swift (decode). Compiled only off the Apple path with the shim present
//  (`#if !canImport(Compression) && canImport(CBrotli)`), so it never collides with Brotli.swift on
//  Darwin; same `compress(_:)` / `decompress(_:maxOutput:)` shapes so the middlewares dispatch uniformly.
//

#if !canImport(Compression) && canImport(CBrotli)

    internal import CBrotli

    /// Brotli encode + decode (RFC 7932) via libbrotli (the CBrotli shim).
    enum Brotli {
        /// Encode quality 5 — a strong speed/ratio balance for on-the-fly text (the range is 0…11; 11 is
        /// the densest but far slower, unsuited to per-response encoding).
        private static let quality: Int32 = 5

        /// Compresses `input` into a Brotli stream, or `nil` if it is empty or libbrotli could not encode it.
        static func compress(_ input: [UInt8]) -> [UInt8]? {
            guard !input.isEmpty else {
                return nil
            }
            let capacity = cbrotli_compress_bound(input.count)
            guard capacity > 0 else {
                return nil
            }
            var destination = [UInt8](repeating: 0, count: capacity)
            let written = input.withUnsafeBufferPointer { source in
                destination.withUnsafeMutableBufferPointer { output -> Int in
                    guard let source = source.baseAddress, let output = output.baseAddress else {
                        return 0
                    }
                    return cbrotli_compress(output, capacity, source, input.count, quality)
                }
            }
            guard written > 0 else {
                return nil
            }
            destination.removeLast(destination.count - written)
            return destination
        }

        /// Decompresses a Brotli stream, bounding the output to `maxOutput` octets — over-cap input overruns
        /// the sized buffer and fails closed (nil), the decompression-bomb defense (CWE-409).
        static func decompress(_ input: [UInt8], maxOutput: Int) -> [UInt8]? {
            guard maxOutput > 0, !input.isEmpty else {
                return nil
            }
            let capacity = maxOutput + 1
            var destination = [UInt8](repeating: 0, count: capacity)
            let written = input.withUnsafeBufferPointer { source in
                destination.withUnsafeMutableBufferPointer { output -> Int in
                    guard let source = source.baseAddress, let output = output.baseAddress else {
                        return 0
                    }
                    return cbrotli_decompress(output, capacity, source, input.count)
                }
            }
            guard written > 0, written <= maxOutput else {
                return nil
            }
            destination.removeLast(destination.count - written)
            return destination
        }
    }

#endif
