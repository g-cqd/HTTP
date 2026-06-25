//
//  Inflate.swift
//  HTTPServer
//
//  RFC 1952 — bounded gzip *decompression* (the inbound mirror of Gzip.swift), over Darwin
//  Compression's raw-DEFLATE (RFC 1951) decoder. The output is hard-capped to defend against a
//  decompression bomb (CWE-409): a tiny gzip member can otherwise expand to gigabytes. It strips the
//  fixed 10-octet gzip header and the 8-octet trailer, decodes the DEFLATE payload into a buffer sized
//  to the cap, and fails closed (nil) on an unsupported envelope, a decode error, or an overflow —
//  never a partial body.
//

internal import Compression

/// Decompresses gzip members (RFC 1952) with a hard output bound — the inverse of ``Gzip``.
enum Inflate {
    /// Decompresses a gzip member, bounding the output to `maxOutput` octets (the caller folds in any
    /// ratio cap).
    ///
    /// Returns nil for an unsupported/malformed envelope, a decode error, or output that would exceed
    /// `maxOutput` — fail-closed, the decompression-bomb defense (CWE-409).
    static func gunzip(_ input: [UInt8], maxOutput: Int) -> [UInt8]? {
        // A plain gzip member: magic 1f 8b, CM=8 (deflate), FLG=0 (no extra/name/comment — the form our
        // encoder and the common ones emit), then DEFLATE, then an 8-octet CRC-32 + ISIZE trailer. A
        // non-zero FLG (a variable-length header) is unsupported and rejected, never mis-parsed.
        guard maxOutput > 0, input.count >= 18,
            input[0] == 0x1f, input[1] == 0x8b, input[2] == 0x08, input[3] == 0x00
        else {
            return nil
        }
        let deflate = input[10 ..< (input.count - 8)]
        // Decode into a cap+1 buffer: a body that fits returns ≤ maxOutput; a bomb fills the buffer and
        // returns maxOutput+1, because compression_decode_buffer truncates and returns dst_size when the
        // output does not fit — so `written > maxOutput` is exactly the overflow signal.
        let capacity = maxOutput + 1
        var destination = [UInt8](repeating: 0, count: capacity)
        let written = deflate.withUnsafeBufferPointer { source in
            destination.withUnsafeMutableBufferPointer { destination -> Int in
                guard let source = source.baseAddress, let destination = destination.baseAddress
                else {
                    return 0
                }
                return compression_decode_buffer(
                    destination, capacity, source, deflate.count, nil, COMPRESSION_ZLIB
                )
            }
        }
        guard written > 0, written <= maxOutput else {
            return nil  // 0 = decode error / empty; > maxOutput = a decompression bomb past the cap
        }
        destination.removeLast(destination.count - written)
        return destination
    }
}
