//
//  GzipInflator.swift
//  HTTPDeflate
//
//  RFC 1952 — the gzip member decoder: the §2.3 header (magic, CM=8, the optional FEXTRA / FNAME /
//  FCOMMENT / FHCRC fields, reserved flag bits rejected), the raw DEFLATE body through ``Inflator``,
//  and the §2.3.1 trailer (CRC-32 + ISIZE, both verified — fail closed on either mismatch). One
//  member per instance; octets after the trailer are left at the caller's cursor. Header fields are
//  parsed byte-at-a-time, so the machine suspends losslessly anywhere.
//

internal import HTTPCore

/// The RFC 1952 gzip member decoder: header, DEFLATE body, verified CRC-32/ISIZE trailer.
public struct GzipInflator {
    /// One parsing phase of the member, in §2.3 field order.
    private enum Phase {
        /// The 10 fixed header octets.
        case fixedHeader
        /// The 2-octet XLEN of an FEXTRA field.
        case extraLength
        /// Skipping XLEN extra octets.
        case extraSkip
        /// Skipping a zero-terminated FNAME.
        case name
        /// Skipping a zero-terminated FCOMMENT.
        case comment
        /// The 2-octet FHCRC header checksum.
        case headerChecksum
        /// The DEFLATE body.
        case body
        /// The 8-octet CRC-32 + ISIZE trailer.
        case trailer
        /// The member is complete.
        case finished
    }

    private var phase: Phase = .fixedHeader
    private var inflator = Inflator()
    /// Folds every header octet, in case an FHCRC field asks for the low 16 bits (§2.3.1).
    private var headerCRC = CRC32.Running()
    /// Folds every inflated octet for the trailer check (§2.3.1).
    private var outputCRC = CRC32.Running()
    /// The FLG octet (§2.3.1).
    private var flags: UInt8 = 0
    /// The octet counter of the current fixed-size phase.
    private var counter = 0
    /// The little-endian accumulator of the current multi-octet field.
    private var value = 0
    /// Octets left to skip in an FEXTRA field.
    private var skipRemaining = 0
    /// The trailer's CRC-32, once read.
    private var trailerCRC: UInt32 = 0

    /// Creates a decoder positioned at a member's first octet.
    public init() {
        // All state is fixed here; `run` allocates nothing.
    }

    /// Decodes as much of the member as possible (same pump contract as ``Inflator/run``).
    ///
    /// - Parameters:
    ///   - input: Coded octets of the member (any chunking).
    ///   - inputIndex: The read cursor, advanced past every consumed octet; on
    ///     ``CodecProgress/finished`` it points just past the trailer.
    ///   - output: The destination for inflated octets.
    /// - Returns: The pump progress; ``CodecProgress/finished`` only after the trailer verified.
    /// - Throws: ``InflateError`` on any malformed shape, including CRC-32/ISIZE mismatches.
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
                        outputCRC.update(bytes: output.span.extracting(before ..< output.count))
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

    /// Feeds one octet to whichever header/trailer phase is active.
    private mutating func consume(_ byte: UInt8) throws(InflateError) {
        switch phase {
            case .fixedHeader:
                try consumeFixedHeader(byte)
            case .extraLength:
                headerCRC.update(CollectionOfOne(byte))
                value |= Int(byte) << (8 * counter)
                counter += 1
                if counter == 2 {
                    skipRemaining = value
                    counter = 0
                    value = 0
                    phase = skipRemaining > 0 ? .extraSkip : nextField(after: .extraSkip)
                }
            case .extraSkip:
                headerCRC.update(CollectionOfOne(byte))
                skipRemaining -= 1
                if skipRemaining <= 0 {
                    advanceHeader(past: .extraSkip)
                }
            case .name, .comment:
                headerCRC.update(CollectionOfOne(byte))
                if byte == 0 {
                    advanceHeader(past: phase)
                }
            case .headerChecksum:
                value |= Int(byte) << (8 * counter)
                counter += 1
                if counter == 2 {
                    guard value == Int(headerCRC.checksum & 0xFFFF) else {
                        throw .headerChecksumMismatch  // FHCRC (§2.3.1)
                    }
                    advanceHeader(past: .headerChecksum)
                }
            default:
                try consumeTrailer(byte)
        }
    }

    /// Validates the 10 fixed octets as they arrive (§2.3).
    private mutating func consumeFixedHeader(_ byte: UInt8) throws(InflateError) {
        headerCRC.update(CollectionOfOne(byte))
        switch counter {
            case 0 where byte != 0x1F, 1 where byte != 0x8B:
                throw .invalidGzipHeader  // ID1/ID2 magic (§2.3.1)
            case 2 where byte != 8:
                throw .invalidGzipHeader  // CM: only DEFLATE is defined (§2.3.1)
            case 3:
                guard byte & 0xE0 == 0 else {
                    throw .invalidGzipHeader  // reserved FLG bits must be zero (§2.3.1)
                }
                flags = byte
            default:
                break  // MTIME/XFL/OS carry no constraints (§2.3.1)
        }
        counter += 1
        if counter == 10 {
            advanceHeader(past: .fixedHeader)
        }
    }

    /// Steps to the next present optional field in §2.3 order, then the body.
    private mutating func advanceHeader(past current: Phase) {
        counter = 0
        value = 0
        phase = nextField(after: current)
    }

    /// The first §2.3 field present after `current` (FEXTRA → FNAME → FCOMMENT → FHCRC → body).
    private func nextField(after current: Phase) -> Phase {
        let rank: Int
        switch current {
            case .fixedHeader:
                rank = 0
            case .extraLength, .extraSkip:
                rank = 1
            case .name:
                rank = 2
            case .comment:
                rank = 3
            default:
                rank = 4
        }
        if rank < 1, flags & 0x04 != 0 {
            return .extraLength
        }
        if rank < 2, flags & 0x08 != 0 {
            return .name
        }
        if rank < 3, flags & 0x10 != 0 {
            return .comment
        }
        if rank < 4, flags & 0x02 != 0 {
            return .headerChecksum
        }
        return .body
    }

    /// Accumulates and verifies the CRC-32 then ISIZE trailer octets (§2.3.1).
    private mutating func consumeTrailer(_ byte: UInt8) throws(InflateError) {
        value |= Int(byte) << (8 * (counter & 3))
        counter += 1
        if counter == 4 {
            trailerCRC = UInt32(truncatingIfNeeded: value)
            value = 0
            guard trailerCRC == outputCRC.checksum else {
                throw .checksumMismatch  // CRC-32 over the inflated octets (§2.3.1)
            }
        }
        if counter == 8 {
            let size = UInt32(truncatingIfNeeded: value)
            guard size == UInt32(truncatingIfNeeded: inflator.totalWritten) else {
                throw .sizeMismatch  // ISIZE = inflated length mod 2³² (§2.3.1)
            }
            phase = .finished
        }
    }
}
