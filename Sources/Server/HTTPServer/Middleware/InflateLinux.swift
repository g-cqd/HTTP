//
//  InflateLinux.swift
//  HTTPServer
//
//  Bounded inbound decompression for the non-Apple (Linux) build — the counterpart to Inflate.swift,
//  which uses Darwin Compression. gzip (RFC 1952, CRC-32 + ISIZE verified) and `deflate` (RFC 1950
//  zlib-wrapped with the Adler-32 verified, falling back to RFC 1951 raw for the senders that omit
//  the envelope) decode through the in-house HTTPDeflate codec; Brotli decode comes from the opt-in
//  libbrotli shim. The output is hard-capped against a decompression bomb (CWE-409): a decode into
//  a capacity-bounded destination fails closed (nil) when the body would not fit — never a partial
//  body — and ``BoundedGrowthDecode`` owns the destination growth schedule.
//
//  Compiled only where Apple's Compression framework is absent (`#if !canImport(Compression)`;
//  Inflate.swift is excluded from the Linux graph), with the same `decompress(_:encoding:maxOutput:)`
//  shape so DecompressionMiddleware dispatches uniformly across platforms.
//

#if !canImport(Compression)

    internal import HTTPDeflate

    /// Decompresses a coded request body with a hard output bound — the inverse of ``Gzip``.
    enum Inflate {
        /// Decompresses `input` coded with `encoding` (`gzip`/`deflate`/`br`), bounding the output
        /// to `maxOutput` octets.
        ///
        /// Returns nil for an unsupported/malformed envelope, a decode error, or output that would
        /// exceed `maxOutput` — fail-closed, the decompression-bomb defense (CWE-409).
        static func decompress(_ input: [UInt8], encoding: String, maxOutput: Int) -> [UInt8]? {
            switch encoding {
                case "gzip", "x-gzip":
                    return decode(input, format: .gzip, maxOutput: maxOutput)
                case "deflate":
                    // The spec'd zlib envelope (RFC 1950) first, then raw DEFLATE (RFC 1951) —
                    // some `deflate` senders omit the zlib header.
                    return decode(input, format: .zlib, maxOutput: maxOutput)
                        ?? decode(input, format: .raw, maxOutput: maxOutput)
                #if canImport(CBrotli)
                    case "br":
                        return Brotli.decompress(input, maxOutput: maxOutput)
                #endif
                default:
                    return nil
            }
        }

        /// The bounded decode: ``DeflateCodec/decompress(_:format:capacity:)`` reaches `finished`
        /// only when the whole stream fits its capacity, so a too-small destination reads as nil.
        ///
        /// The retry schedule and the CWE-409 cap live in ``BoundedGrowthDecode``, shared with the
        /// libbrotli shim — the rationale for growing geometrically rather than sizing to the cap
        /// is documented there, once, and tested by `BoundedGrowthDecodeTests`.
        private static func decode(
            _ input: [UInt8], format: DeflateCodec.Format, maxOutput: Int
        ) -> [UInt8]? {
            guard !input.isEmpty else {
                return nil
            }
            return BoundedGrowthDecode.run(maxOutput: maxOutput) {
                DeflateCodec.decompress(input, format: format, capacity: $0)
            }
        }
    }

#endif
