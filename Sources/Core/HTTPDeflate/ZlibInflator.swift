//
//  ZlibInflator.swift
//  HTTPDeflate
//
//  RFC 1950 — the zlib envelope decoder behind the `deflate` content coding: the 2-octet CMF/FLG
//  header (CM must be 8, CINFO ≤ 7, the check value must divide by 31, and FDICT is rejected — a
//  server cannot have negotiated a preset dictionary), the raw DEFLATE body through ``Inflator``,
//  and the big-endian Adler-32 trailer, verified against the inflated octets (fail closed).
//

/// The RFC 1950 zlib envelope decoder: header, DEFLATE body, verified Adler-32 trailer.
public struct ZlibInflator {
    /// One parsing phase of the envelope, in §2.2 order.
    private enum Phase {
        /// The CMF/FLG octet pair.
        case header
        /// The DEFLATE body.
        case body
        /// The 4-octet big-endian Adler-32.
        case trailer
        /// The envelope is complete.
        case finished
    }

    private var phase: Phase = .header
    private var inflator = Inflator()
    /// Folds every inflated octet for the trailer check (§2.2).
    private var adler = Adler32()
    /// The octet counter of the current fixed-size phase.
    private var counter = 0
    /// The CMF octet, kept for the two-octet check value; then the big-endian trailer accumulator.
    private var value = 0

    /// Creates a decoder positioned at the envelope's first octet.
    public init() {
        // All state is fixed here; `run` allocates nothing.
    }

    /// Decodes as much of the envelope as possible (same pump contract as ``Inflator/run``).
    ///
    /// - Parameters:
    ///   - input: Coded octets of the envelope (any chunking).
    ///   - inputIndex: The read cursor, advanced past every consumed octet; on
    ///     ``CodecProgress/finished`` it points just past the Adler-32.
    ///   - output: The destination for inflated octets.
    /// - Returns: The pump progress; ``CodecProgress/finished`` only after the trailer verified.
    /// - Throws: ``InflateError`` on any malformed shape, including an Adler-32 mismatch.
    public mutating func run(
        input: Span<UInt8>, from inputIndex: inout Int, into output: inout OutputSpan<UInt8>
    ) throws(InflateError) -> CodecProgress {
        while true {
            switch phase {
                case .body:
                    let before = output.count
                    let progress = try inflator.run(
                        input: input, from: &inputIndex, into: &output
                    )
                    if output.count > before {
                        adler.update(output.span.extracting(before ..< output.count))
                    }
                    guard progress == .finished else {
                        return progress
                    }
                    phase = .trailer
                    counter = 0
                    value = 0
                case .finished:
                    return .finished
                default:
                    guard inputIndex < input.count else {
                        return .needsInput
                    }
                    let byte = input[inputIndex]
                    inputIndex += 1
                    try consume(byte)
            }
        }
    }

    /// Feeds one octet to the header or trailer phase.
    private mutating func consume(_ byte: UInt8) throws(InflateError) {
        if phase == .header {
            try consumeHeader(byte)
            return
        }
        value = (value << 8) | Int(byte)  // the Adler-32 is big-endian (§2.2)
        counter += 1
        if counter == 4 {
            guard UInt32(truncatingIfNeeded: value) == adler.checksum else {
                throw .adlerMismatch  // ADLER32 over the inflated octets (§2.2)
            }
            phase = .finished
        }
    }

    /// Validates CMF then FLG (§2.2).
    private mutating func consumeHeader(_ byte: UInt8) throws(InflateError) {
        if counter == 0 {
            guard byte & 0x0F == 8, byte >> 4 <= 7 else {
                throw .invalidZlibHeader  // CM must be DEFLATE, CINFO ≤ 7 (§2.2)
            }
            value = Int(byte)
            counter = 1
            return
        }
        guard (value << 8 | Int(byte)) % 31 == 0 else {
            throw .invalidZlibHeader  // FCHECK: CMF·256 + FLG ≡ 0 (mod 31) (§2.2)
        }
        guard byte & 0x20 == 0 else {
            throw .invalidZlibHeader  // FDICT: no preset dictionary was negotiated (§2.2)
        }
        phase = .body
        counter = 0
        value = 0
    }
}
