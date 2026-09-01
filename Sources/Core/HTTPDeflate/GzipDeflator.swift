//
//  GzipDeflator.swift
//  HTTPDeflate
//
//  RFC 1952 — the gzip member encoder: the fixed 10-octet header (no flags, no mtime, OS =
//  unknown — the same deterministic envelope the Darwin coding emits, so gzip output never varies
//  by host), the raw DEFLATE body through ``Deflator``, and the §2.3.1 trailer (CRC-32 over the
//  plain octets via HTTPCore's accelerated kernel + ISIZE), folded incrementally so the member
//  streams without retaining the body. Byte-identity between one-shot and streamed use is
//  structural: both are this one type driven with different chunk sizes, and the underlying
//  ``Deflator`` is chunk-stable under ``DeflateFlush/none``.
//

internal import HTTPCore

/// The RFC 1952 gzip member encoder over ``Deflator``, with incremental CRC-32/ISIZE folding.
public struct GzipDeflator {
    /// The fixed header: ID1/ID2, CM=8, FLG=0, MTIME=0, XFL=0, OS=255 (§2.3).
    static let header: [UInt8] = [0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF]

    /// Where the member stands.
    private enum Phase {
        /// Compressing body octets (the header may still be draining).
        case body
        /// The trailer is staged in ``framing`` and draining.
        case trailer
        /// The member is complete.
        case finished
    }

    private var phase: Phase = .body
    private var deflator: Deflator
    /// The running CRC-32 of every consumed plain octet (§2.3.1).
    private var crc = CRC32.Running()
    /// Total plain octets consumed — the trailer's ISIZE mod 2³² (§2.3.1).
    private var totalInput = 0
    /// The header, then the trailer, staged for draining around the DEFLATE body.
    private var framing: [UInt8]
    private var framingIndex = 0

    /// Creates an encoder at `level` with the header staged.
    ///
    /// - Parameter level: The DEFLATE effort grade (fixed for the member).
    public init(level: DeflateLevel = .balanced) {
        deflator = Deflator(level: level)
        framing = Self.header
    }

    /// Compresses as much as possible (same pump contract as ``Deflator/run``).
    ///
    /// - Parameters:
    ///   - input: The plain octets to compress.
    ///   - inputIndex: The read cursor, advanced past every consumed octet.
    ///   - output: The destination for the gzip member's octets.
    ///   - flush: The boundary to arm; ``DeflateFlush/finish`` seals the member with its trailer.
    /// - Returns: The pump progress; ``CodecProgress/finished`` once the trailer fully drained.
    public mutating func run(
        input: Span<UInt8>,
        from inputIndex: inout Int,
        into output: inout OutputSpan<UInt8>,
        flush: DeflateFlush = .none
    ) -> CodecProgress {
        while true {
            while framingIndex < framing.count, output.freeCapacity > 0 {
                output.append(framing[framingIndex])
                framingIndex += 1
            }
            guard framingIndex == framing.count else {
                return .needsOutput
            }
            switch phase {
                case .body:
                    let before = inputIndex
                    let progress = deflator.run(
                        input: input, from: &inputIndex, into: &output, flush: flush
                    )
                    if inputIndex > before {
                        crc.update(bytes: input.extracting(before ..< inputIndex))
                        totalInput += inputIndex - before
                    }
                    guard progress == .finished else {
                        return progress
                    }
                    stageTrailer()
                case .trailer:
                    phase = .finished  // the framing drain above emptied the trailer
                case .finished:
                    return .finished
            }
        }
    }

    /// Stages the CRC-32 + ISIZE trailer, both little-endian (§2.3.1).
    private mutating func stageTrailer() {
        var trailer: [UInt8] = []
        trailer.reserveCapacity(8)
        appendLittleEndian(crc.checksum, to: &trailer)
        appendLittleEndian(UInt32(truncatingIfNeeded: totalInput), to: &trailer)
        framing = trailer
        framingIndex = 0
        phase = .trailer
    }

    /// Appends `value` in the trailer's little-endian octet order (§2.3.1).
    private func appendLittleEndian(_ value: UInt32, to output: inout [UInt8]) {
        output.append(UInt8(value & 0xFF))
        output.append(UInt8((value >> 8) & 0xFF))
        output.append(UInt8((value >> 16) & 0xFF))
        output.append(UInt8((value >> 24) & 0xFF))
    }
}
