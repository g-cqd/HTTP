//
//  Gzip.swift
//  HTTPServer
//
//  RFC 1952 — gzip framing around Darwin `Compression`. The Compression framework's `COMPRESSION_ZLIB`
//  produces a raw DEFLATE stream (RFC 1951); gzip wraps that in a 10-octet header, then appends the
//  CRC-32 and the input size (ISIZE). The DEFLATE itself is the framework's job; this adds the envelope.
//

internal import Compression
internal import HTTPCore

/// Produces gzip members (RFC 1952) by wrapping Darwin's raw-DEFLATE encoder.
enum Gzip {

    /// The fixed gzip header: magic, CM=deflate, no flags, no mtime, no extra flags, OS=unknown.
    private static let header: [UInt8] = [
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
    ]

    /// Compresses `input` into a gzip member, or `nil` if it is empty or DEFLATE could not encode it.
    static func compress(_ input: [UInt8]) -> [UInt8]? {
        guard !input.isEmpty, let deflated = deflate(input) else { return nil }
        var out = header
        out.reserveCapacity(header.count + deflated.count + 8)
        out.append(contentsOf: deflated)
        appendLittleEndian(CRC32.checksum(input), to: &out)
        appendLittleEndian(UInt32(truncatingIfNeeded: input.count), to: &out)  // ISIZE mod 2^32
        return out
    }

    /// Raw DEFLATE (RFC 1951) via `compression_encode_buffer`, or `nil` if the output did not fit.
    private static func deflate(_ input: [UInt8]) -> [UInt8]? {
        // Headroom so incompressible input (DEFLATE can expand slightly) still fits in one shot.
        let capacity = input.count + (input.count / 2) + 64
        var destination = [UInt8](repeating: 0, count: capacity)
        let written = input.withUnsafeBufferPointer { source in
            destination.withUnsafeMutableBufferPointer { destination -> Int in
                guard let source = source.baseAddress, let destination = destination.baseAddress
                else { return 0 }
                return compression_encode_buffer(
                    destination, capacity, source, input.count, nil, COMPRESSION_ZLIB)
            }
        }
        guard written > 0 else { return nil }
        destination.removeLast(destination.count - written)
        return destination
    }

    private static func appendLittleEndian(_ value: UInt32, to output: inout [UInt8]) {
        output.append(UInt8(value & 0xFF))
        output.append(UInt8((value >> 8) & 0xFF))
        output.append(UInt8((value >> 16) & 0xFF))
        output.append(UInt8((value >> 24) & 0xFF))
    }
}
