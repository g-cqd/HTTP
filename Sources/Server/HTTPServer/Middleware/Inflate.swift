//
//  Inflate.swift
//  HTTPServer
//
//  Bounded inbound decompression (the inbound mirror of Gzip.swift) over Darwin Compression: gzip
//  (RFC 1952), `deflate` (raw RFC 1951 or zlib-wrapped RFC 1950), and Brotli (RFC 7932). The output is
//  hard-capped to defend against a decompression bomb (CWE-409): a tiny coded body can otherwise expand
//  to gigabytes. Every path fails closed (nil) on an unsupported envelope, a decode error, or an
//  overflow — never a partial body. gzip's CRC-32/ISIZE and zlib's Adler-32 trailers are verified, so a
//  corrupt member is rejected rather than mis-decoded.
//
//  The cap is a *refusal threshold*, not an allocation. Decoding runs incrementally through
//  `compression_stream` in ``window``-sized steps, and the output grows geometrically into whatever
//  the member actually produces, so a 1 GiB cap costs 1 GiB only if 1 GiB is genuinely decoded. The
//  earlier one-shot form sized a single `maxOutput + 1` buffer up front, which made a small coded body
//  under a default-scale cap an enormous per-request allocation, and made `maxOutput == Int.max`
//  overflow and trap.
//

internal import Compression
internal import HTTPCore

/// Decompresses a coded request body with a hard output bound — the inverse of ``Gzip``.
enum Inflate {
    /// The incremental decode step, in octets.
    ///
    /// Output is produced one window at a time and appended, so the transient scratch is this size
    /// whatever the cap is. 64 KiB is large enough that the per-step `compression_stream_process`
    /// overhead is noise against the copy, and small enough to be irrelevant next to any body worth
    /// decoding.
    private static let window = 64 * 1_024

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
    /// HTTP `deflate` is raw DEFLATE for most clients, but some send a zlib wrapper. The wrapper is
    /// tried first because it is self-identifying (``ZlibWrapper`` validates CM, CINFO, FDICT and the
    /// FCHECK multiple-of-31 rule), and its Adler-32 must then match the decoded output; anything that
    /// does not present as a sound zlib stream falls back to raw DEFLATE.
    private static func inflateDeflate(_ input: [UInt8], maxOutput: Int) -> [UInt8]? {
        if let wrapper = ZlibWrapper(input),
            let output = decode(wrapper.payload, algorithm: COMPRESSION_ZLIB, maxOutput: maxOutput),
            wrapper.checksumMatches(output)
        {
            return output
        }
        return decode(input[...], algorithm: COMPRESSION_ZLIB, maxOutput: maxOutput)
    }

    /// The shared bounded decode: incremental, failing closed (nil) on a decode error, on empty
    /// output, or the moment the output would pass `maxOutput` (CWE-409).
    ///
    /// The scratch window is `min(maxOutput, window)`, so a small cap does not reserve a large step
    /// and a large cap does not reserve the cap.
    private static func decode(
        _ source: ArraySlice<UInt8>,
        algorithm: compression_algorithm,
        maxOutput: Int
    ) -> [UInt8]? {
        guard maxOutput > 0, !source.isEmpty else {
            return nil
        }
        var scratch = [UInt8](repeating: 0, count: min(maxOutput, window))
        return source.withUnsafeBufferPointer { input in
            scratch.withUnsafeMutableBufferPointer { destination in
                pump(input, into: destination, algorithm: algorithm, maxOutput: maxOutput)
            }
        }
    }

    /// Runs one decode stream from `input` to completion, one `destination`-sized step at a time.
    ///
    /// The bound is checked *before* each produced step is appended, so an over-cap member is refused
    /// without its expansion ever being retained; the output array grows geometrically into whatever
    /// the member actually produces. A step that neither ends the stream nor produces an octet would
    /// spin forever on a malformed member, so it is refused too.
    private static func pump(
        _ input: UnsafeBufferPointer<UInt8>,
        into destination: UnsafeMutableBufferPointer<UInt8>,
        algorithm: compression_algorithm,
        maxOutput: Int
    ) -> [UInt8]? {
        guard let source = input.baseAddress, let target = destination.baseAddress else {
            return nil
        }
        var stream = compression_stream(
            dst_ptr: target,
            dst_size: destination.count,
            src_ptr: source,
            src_size: input.count,
            state: nil
        )
        guard
            compression_stream_init(&stream, COMPRESSION_STREAM_DECODE, algorithm)
                == COMPRESSION_STATUS_OK
        else {
            return nil
        }
        defer { compression_stream_destroy(&stream) }
        // `compression_stream_init` resets the descriptor, so the whole input is offered after it.
        stream.src_ptr = source
        stream.src_size = input.count
        var output: [UInt8] = []
        output.reserveCapacity(destination.count)
        while true {
            stream.dst_ptr = target
            stream.dst_size = destination.count
            let status = compression_stream_process(
                &stream, Int32(COMPRESSION_STREAM_FINALIZE.rawValue)
            )
            let produced = destination.count - stream.dst_size
            // `maxOutput - produced` is non-negative (`produced <= destination.count <= maxOutput`),
            // so the comparison cannot overflow the way `output.count + produced` could.
            guard status != COMPRESSION_STATUS_ERROR, output.count <= maxOutput - produced else {
                return nil
            }
            output.append(contentsOf: UnsafeBufferPointer(start: target, count: produced))
            guard status != COMPRESSION_STATUS_END else {
                return output.isEmpty ? nil : output
            }
            guard produced > 0 else {
                return nil
            }
        }
    }
}
