//
//  Inflate.swift
//  HTTPServer
//
//  Bounded inbound decompression (the inbound mirror of Gzip.swift) over Darwin Compression: gzip
//  (RFC 1952), `deflate` (raw RFC 1951 or zlib-wrapped RFC 1950), and Brotli (RFC 7932). The output is
//  hard-capped to defend against a decompression bomb (CWE-409): a tiny coded body can otherwise expand
//  to gigabytes. Every path decodes into a buffer sized to the cap and fails closed (nil) on an
//  unsupported envelope, a decode error, or an overflow — never a partial body. For gzip the CRC-32 and
//  ISIZE trailer are verified, so a corrupt member is rejected rather than mis-decoded.
//

internal import Compression
internal import HTTPCore

/// Decompresses a coded request body with a hard output bound — the inverse of ``Gzip``.
enum Inflate {
    /// Decompresses `input` coded with `encoding` (`gzip`/`deflate`/`br`), bounding the output to
    /// `maxOutput` octets (the caller folds in any ratio cap).
    ///
    /// Returns nil for an unsupported/malformed envelope, a decode error, or output that would exceed
    /// `maxOutput` — fail-closed, the decompression-bomb defense (CWE-409).
    static func decompress(_ input: [UInt8], encoding: String, maxOutput: Int) -> [UInt8]? {
        switch encoding {
            case "gzip", "x-gzip":
                return gunzip(input, maxOutput: maxOutput)
            case "deflate":
                return inflateDeflate(input, maxOutput: maxOutput)
            case "br":
                return decode(input[...], algorithm: COMPRESSION_BROTLI, maxOutput: maxOutput)
            default:
                return nil
        }
    }

    /// Decompresses a gzip member (RFC 1952): parse the (possibly flagged) header, decode the DEFLATE
    /// payload under the cap, then verify the CRC-32 / ISIZE trailer.
    static func gunzip(_ input: [UInt8], maxOutput: Int) -> [UInt8]? {
        guard let payload = gzipPayload(input),
            let output = decode(payload, algorithm: COMPRESSION_ZLIB, maxOutput: maxOutput),
            gzipTrailerMatches(input, output: output)
        else {
            return nil
        }
        return output
    }

    /// The DEFLATE payload of a gzip member — the bytes after the (possibly flagged) header and before
    /// the 8-octet trailer (RFC 1952 §2.3.1), or nil for an unsupported/malformed envelope.
    private static func gzipPayload(_ input: [UInt8]) -> ArraySlice<UInt8>? {
        // magic 1f 8b, CM=8 (deflate), and a minimal member (10-octet header + 8-octet trailer).
        guard input.count >= 18, input[0] == 0x1f, input[1] == 0x8b, input[2] == 0x08 else {
            return nil
        }
        let flags = input[3]
        guard flags & 0xe0 == 0 else {
            return nil  // a reserved FLG bit is set — unsupported, never mis-parsed
        }
        let limit = input.count - 8
        var index = 10
        if flags & 0x04 != 0 {  // FEXTRA: a 2-octet length then that many octets
            guard index + 2 <= limit else {
                return nil
            }
            index += 2 + (Int(input[index]) | Int(input[index + 1]) << 8)
        }
        if flags & 0x08 != 0, let next = afterZeroByte(input, from: index, limit: limit) {
            index = next  // FNAME
        }
        else if flags & 0x08 != 0 {
            return nil
        }
        if flags & 0x10 != 0, let next = afterZeroByte(input, from: index, limit: limit) {
            index = next  // FCOMMENT
        }
        else if flags & 0x10 != 0 {
            return nil
        }
        if flags & 0x02 != 0 {
            index += 2  // FHCRC
        }
        guard index >= 10, index <= limit else {
            return nil
        }
        return input[index ..< limit]
    }

    /// The index just past the next zero byte in `input[from..<limit]`, or nil if there is none.
    private static func afterZeroByte(_ input: [UInt8], from start: Int, limit: Int) -> Int? {
        var index = start
        while index < limit {
            if input[index] == 0 {
                return index + 1
            }
            index += 1
        }
        return nil
    }

    /// Whether the gzip CRC-32 and ISIZE trailer match the decoded `output` (RFC 1952 §2.3.1).
    private static func gzipTrailerMatches(_ input: [UInt8], output: [UInt8]) -> Bool {
        let end = input.count
        let crc = littleEndian(input, at: end - 8)
        let isize = littleEndian(input, at: end - 4)
        return crc == CRC32.checksum(output) && isize == UInt32(truncatingIfNeeded: output.count)
    }

    /// The little-endian `UInt32` at `offset` (the caller guarantees `offset + 4 <= count`).
    private static func littleEndian(_ input: [UInt8], at offset: Int) -> UInt32 {
        UInt32(input[offset]) | UInt32(input[offset + 1]) << 8 | UInt32(input[offset + 2]) << 16
            | UInt32(input[offset + 3]) << 24
    }

    /// `Content-Encoding: deflate` — raw DEFLATE (RFC 1951) or a zlib wrapper (RFC 1950).
    ///
    /// HTTP `deflate` is raw DEFLATE for most clients, but some send a zlib wrapper. Try raw first; on
    /// failure, strip the 2-octet zlib header and 4-octet Adler-32 trailer and retry.
    private static func inflateDeflate(_ input: [UInt8], maxOutput: Int) -> [UInt8]? {
        if let raw = decode(input[...], algorithm: COMPRESSION_ZLIB, maxOutput: maxOutput) {
            return raw
        }
        guard input.count >= 6 else {
            return nil
        }
        return decode(
            input[2 ..< (input.count - 4)], algorithm: COMPRESSION_ZLIB, maxOutput: maxOutput
        )
    }

    /// The shared bounded decode: into a `cap + 1` buffer, rejecting a decode error / empty (0) and an
    /// overflow (`> maxOutput`) — `compression_decode_buffer` returns `dst_size` when the output does not
    /// fit, so `written > maxOutput` is exactly the bomb signal (CWE-409).
    private static func decode(
        _ source: ArraySlice<UInt8>,
        algorithm: compression_algorithm,
        maxOutput: Int
    ) -> [UInt8]? {
        guard maxOutput > 0, !source.isEmpty else {
            return nil
        }
        let capacity = maxOutput + 1
        var destination = [UInt8](repeating: 0, count: capacity)
        let written = source.withUnsafeBufferPointer { input in
            destination.withUnsafeMutableBufferPointer { output -> Int in
                guard let input = input.baseAddress, let output = output.baseAddress else {
                    return 0
                }
                return compression_decode_buffer(
                    output, capacity, input, source.count, nil, algorithm
                )
            }
        }
        guard written > 0, written <= maxOutput else {
            return nil
        }
        destination.removeLast(destination.count - written)
        return destination
    }
}
