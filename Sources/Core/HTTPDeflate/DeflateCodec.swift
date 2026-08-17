//
//  DeflateCodec.swift
//  HTTPDeflate
//
//  The buffered one-shots over the streaming pumps — the shapes the content-coding middleware
//  actually calls: a whole gzip member from a whole body (RFC 1952), and a bounded decode of a
//  gzip / zlib / raw-DEFLATE body into at most `capacity` octets. The bounded decode is the
//  `BoundedGrowthDecode` attempt primitive: nil means "malformed or would not fit", never a
//  partial body (CWE-409, fail closed). One-shot and streamed gzip are byte-identical by
//  construction — both are ``GzipDeflator`` driven with different chunk sizes.
//

/// Buffered one-shot DEFLATE codings (gzip encode; bounded gzip/zlib/raw decode).
public enum DeflateCodec {
    /// The container a coded body arrives in.
    public enum Format: Sendable, Equatable {
        /// An RFC 1952 gzip member (verified CRC-32 + ISIZE).
        case gzip
        /// An RFC 1950 zlib envelope (verified Adler-32) — the spec'd `deflate` coding.
        case zlib
        /// A bare RFC 1951 stream — the `deflate` senders that omit the zlib envelope.
        case raw
    }

    /// Compresses `input` into one whole gzip member (RFC 1952).
    ///
    /// - Parameters:
    ///   - input: The plain octets.
    ///   - level: The DEFLATE effort grade.
    /// - Returns: The complete member (header, body, CRC-32 + ISIZE trailer).
    public static func gzip(_ input: [UInt8], level: DeflateLevel = .balanced) -> [UInt8] {
        var encoder = GzipDeflator(level: level)
        var output: [UInt8] = []
        output.reserveCapacity(input.count / 2 + 64)
        encoder.pump(input, appendingTo: &output, flush: .finish)
        return output
    }

    /// Decodes a whole coded body into at most `capacity` octets, or nil.
    ///
    /// - Parameters:
    ///   - input: The complete coded body (trailing octets past the stream are tolerated,
    ///     matching zlib's one-shot behavior).
    ///   - format: The container to expect.
    ///   - capacity: The output bound; a body inflating past it fails (CWE-409's attempt
    ///     primitive — `BoundedGrowthDecode` owns the retry schedule).
    /// - Returns: The inflated octets, or nil for a malformed/truncated stream, a failed
    ///   checksum, or output past `capacity` — fail closed, never a partial body.
    public static func decompress(
        _ input: [UInt8], format: Format, capacity: Int
    ) -> [UInt8]? {
        guard capacity > 0, !input.isEmpty else {
            return nil
        }
        var decoder = ContainerInflator(format)
        var output: [UInt8] = []
        var index = 0
        var progress: CodecProgress?
        output.append(addingCapacity: capacity) { span in
            progress = SpanBridge.withSpan(of: input) { inputSpan in
                try? decoder.run(input: inputSpan, from: &index, into: &span)
            }
        }
        guard progress == .finished, output.count <= capacity else {
            return nil  // malformed (nil), truncated (needsInput), or over the bound
        }
        return output
    }
}
