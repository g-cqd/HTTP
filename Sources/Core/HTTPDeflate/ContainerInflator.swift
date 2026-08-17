//
//  ContainerInflator.swift
//  HTTPDeflate
//
//  The three container decoders — raw RFC 1951, gzip (RFC 1952), zlib (RFC 1950) — behind one
//  dispatch, so ``DeflateCodec``'s bounded one-shot has a single pump loop instead of three.
//

/// The three container decoders behind one dispatch, so the one-shot has a single pump loop.
enum ContainerInflator {
    case raw(Inflator)
    case gzip(GzipInflator)
    case zlib(ZlibInflator)

    /// Creates the decoder for `format`.
    init(_ format: DeflateCodec.Format) {
        switch format {
            case .raw:
                self = .raw(Inflator())
            case .gzip:
                self = .gzip(GzipInflator())
            case .zlib:
                self = .zlib(ZlibInflator())
        }
    }

    /// Forwards one pump step to the wrapped decoder.
    mutating func run(
        input: Span<UInt8>, from inputIndex: inout Int, into output: inout OutputSpan<UInt8>
    ) throws(InflateError) -> CodecProgress {
        switch self {
            case .raw(var inflator):
                let progress = try inflator.run(input: input, from: &inputIndex, into: &output)
                self = .raw(inflator)
                return progress
            case .gzip(var inflator):
                let progress = try inflator.run(input: input, from: &inputIndex, into: &output)
                self = .gzip(inflator)
                return progress
            case .zlib(var inflator):
                let progress = try inflator.run(input: input, from: &inputIndex, into: &output)
                self = .zlib(inflator)
                return progress
        }
    }
}
