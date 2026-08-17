//
//  DeflateBitWriter.swift
//  HTTPDeflate
//
//  RFC 1951 §3.1.1 — the LSB-first bit packer behind the compressor. Bits accumulate in a 64-bit
//  register and spill into a fixed pending buffer the pump drains into the caller's `OutputSpan`;
//  the buffer is sized by the block encoder's worst case and allocated once, so steady-state writes
//  never allocate. Huffman codes are handed in pre-reversed (see DeflateTables), so a code is
//  written with the same `writeBits` as extra bits and lengths.
//

/// The compressor's LSB-first bit packer over a fixed, drainable pending buffer (RFC 1951 §3.1.1).
struct DeflateBitWriter {
    /// The spilled whole octets awaiting drain.
    private var pending: [UInt8]
    /// The drain cursor into ``pending``.
    private var readIndex = 0
    /// The spill cursor into ``pending``.
    private var writeIndex = 0
    /// Up to 7 not-yet-spilled bits (low bits first).
    private var bitBuffer: UInt64 = 0
    /// How many low bits of ``bitBuffer`` are real (always < 8 between calls).
    private var bitCount = 0

    /// Creates a writer whose pending buffer holds `capacity` octets — the caller's proven
    /// worst-case block size.
    init(capacity: Int) {
        pending = [UInt8](repeating: 0, count: capacity)
    }

    /// Whether any whole octet awaits draining.
    var hasPendingBytes: Bool {
        readIndex < writeIndex
    }

    /// Appends the low `count` bits of `value` (LSB first; `count` ≤ 48).
    mutating func writeBits(_ value: Int, _ count: Int) {
        bitBuffer |= UInt64(value) << UInt64(bitCount)
        bitCount += count
        while bitCount >= 8 {
            pending[writeIndex] = UInt8(bitBuffer & 0xFF)
            writeIndex += 1
            bitBuffer >>= 8
            bitCount -= 8
        }
    }

    /// Zero-pads to the next byte boundary (§3.2.4 stored alignment / end-of-stream padding).
    mutating func alignToByte() {
        if bitCount != 0 {
            writeBits(0, 8 - bitCount)
        }
    }

    /// Appends one whole octet (callers align first; stored-block payloads and container framing).
    mutating func writeByte(_ byte: UInt8) {
        writeBits(Int(byte), 8)
    }

    /// Appends a 16-bit little-endian value (§3.2.4's LEN/NLEN; container trailers).
    mutating func writeLittleEndian16(_ value: Int) {
        writeByte(UInt8(value & 0xFF))
        writeByte(UInt8((value >> 8) & 0xFF))
    }

    /// Moves pending octets into `output`; true once the pending buffer is empty (sub-octet bits
    /// stay buffered — they belong to the next block).
    mutating func drain(into output: inout OutputSpan<UInt8>) -> Bool {
        while readIndex < writeIndex, output.freeCapacity > 0 {
            output.append(pending[readIndex])
            readIndex += 1
        }
        guard readIndex == writeIndex else {
            return false
        }
        readIndex = 0
        writeIndex = 0
        return true
    }

    /// Forgets everything buffered — the compressor's reset.
    mutating func reset() {
        readIndex = 0
        writeIndex = 0
        bitBuffer = 0
        bitCount = 0
    }
}
