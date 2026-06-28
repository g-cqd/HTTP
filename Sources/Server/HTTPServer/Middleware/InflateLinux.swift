//
//  InflateLinux.swift
//  HTTPServer
//
//  Bounded inbound decompression for the non-Apple (Linux) build — the counterpart to Inflate.swift,
//  which uses Darwin Compression. gzip (RFC 1952) and `deflate` (RFC 1951 raw / RFC 1950 zlib-wrapped)
//  decode through the system zlib (the CZlibCoding shim, which auto-detects the gzip/zlib header and
//  verifies the gzip CRC-32/ISIZE trailer itself); Brotli decode comes from the opt-in libbrotli shim.
//  The output is hard-capped against a decompression bomb (CWE-409): the decode buffer is sized to the
//  cap, so an over-cap expansion overruns it and fails closed (nil) — never a partial body.
//
//  Compiled only where the shim is present (`#if canImport(CZlibCoding)`, the Linux graph; Inflate.swift
//  is excluded there), with the same `decompress(_:encoding:maxOutput:)` shape so DecompressionMiddleware
//  dispatches uniformly across platforms.
//

#if canImport(CZlibCoding)

    internal import CZlibCoding

    /// Decompresses a coded request body with a hard output bound — the inverse of ``Gzip``, over zlib.
    enum Inflate {
        /// Decompresses `input` coded with `encoding` (`gzip`/`deflate`/`br`), bounding the output to
        /// `maxOutput` octets.
        ///
        /// Returns nil for an unsupported/malformed envelope, a decode error, or output that would exceed
        /// `maxOutput` — fail-closed, the decompression-bomb defense (CWE-409).
        static func decompress(_ input: [UInt8], encoding: String, maxOutput: Int) -> [UInt8]? {
            switch encoding {
                case "gzip", "x-gzip":
                    // windowBits 47 auto-detects the gzip header and checks the CRC-32/ISIZE trailer.
                    return decode(input, maxOutput: maxOutput, raw: false)
                case "deflate":
                    // zlib-wrapped (RFC 1950) first (auto-detected), then raw DEFLATE (RFC 1951) — some
                    // `deflate` senders omit the zlib header.
                    return decode(input, maxOutput: maxOutput, raw: false)
                        ?? decode(input, maxOutput: maxOutput, raw: true)
                #if canImport(CBrotli)
                    case "br":
                        return Brotli.decompress(input, maxOutput: maxOutput)
                #endif
                default:
                    return nil
            }
        }

        /// The shared bounded decode into a `maxOutput + 1` buffer: zlib reaches `Z_STREAM_END` only when
        /// the whole stream fits, so an over-cap body overruns `avail_out` and the shim returns 0 (nil
        /// here). `raw` selects raw DEFLATE (no zlib/gzip header) over the auto-detecting path.
        private static func decode(_ input: [UInt8], maxOutput: Int, raw: Bool) -> [UInt8]? {
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
                    return raw
                        ? czlib_inflate_raw(output, capacity, source, input.count)
                        : czlib_inflate(output, capacity, source, input.count)
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
