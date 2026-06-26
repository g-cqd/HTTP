//
//  Brotli.swift
//  HTTPServer
//
//  RFC 7932 — Brotli content coding via Darwin `Compression`. Unlike gzip there is no envelope: the
//  `br` content coding is the raw Brotli stream, so this is just the framework's one-shot encoder with
//  output headroom (the inbound mirror is `Inflate`'s `COMPRESSION_BROTLI` path). Apple's framework
//  implements the Brotli level-2 encoder — fast, a good ratio for on-the-fly text, and decodable by any
//  Brotli decoder. The portable/Linux encoder (a `libbrotlienc` shim) is a separate track (gap G0).
//

internal import Compression

/// Produces a `br` content-coding body (RFC 7932) with Darwin's one-shot Brotli encoder.
enum Brotli {
    /// Compresses `input` into a raw Brotli stream, or `nil` if it is empty or the encoder could not fit
    /// the output in one shot.
    static func compress(_ input: [UInt8]) -> [UInt8]? {
        guard !input.isEmpty else {
            return nil
        }
        // Headroom so an incompressible input (Brotli can expand slightly) still fits in one shot.
        let capacity = input.count + (input.count / 2) + 64
        var destination = [UInt8](repeating: 0, count: capacity)
        let written = input.withUnsafeBufferPointer { source in
            destination.withUnsafeMutableBufferPointer { destination -> Int in
                guard let source = source.baseAddress, let destination = destination.baseAddress
                else { return 0 }
                return compression_encode_buffer(
                    destination, capacity, source, input.count, nil, COMPRESSION_BROTLI
                )
            }
        }
        guard written > 0 else {
            return nil
        }
        destination.removeLast(destination.count - written)
        return destination
    }
}
