//
//  DeflateTables.swift
//  HTTPDeflate
//
//  RFC 1951 §3.2.5 / §3.2.6 — the compressor's static lookup tables: match length → length code
//  (257…285) with its base and extra bits, match distance → distance code (0…29) via the two-tier
//  lookup (exact for 1…256, `(distance − 1) >> 7` beyond), and the §3.2.6 fixed Huffman codes.
//  Every code is stored bit-reversed, because §3.1.1 packs Huffman codes most-significant-bit first
//  into an LSB-first stream and the writer emits low bits first.
//

/// The compressor's static RFC 1951 tables (length/distance coding and the §3.2.6 fixed codes).
enum DeflateTables {
    /// The shortest and longest match (§3.2.5).
    static let minMatch = 3
    /// The longest match (§3.2.5).
    static let maxMatch = 258

    /// Length-code bases: code `257 + index` encodes lengths from `base` (§3.2.5).
    static let baseLength: [Int] = [
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
        35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258
    ]

    /// Extra bits per length code (§3.2.5).
    static let extraLengthBits: [Int] = [
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
        3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0
    ]

    /// Distance-code bases (§3.2.5).
    static let baseDistance: [Int] = [
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
        257, 385, 513, 769, 1_025, 1_537, 2_049, 3_073, 4_097, 6_145,
        8_193, 12_289, 16_385, 24_577
    ]

    /// Extra bits per distance code (§3.2.5).
    static let extraDistanceBits: [Int] = [
        0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
        7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13
    ]

    /// Maps `length − 3` (0…255) to its length-code index 0…28 (§3.2.5; 258 maps to code 28).
    static let lengthCode: [UInt8] = {
        var table = [UInt8](repeating: 0, count: 256)
        for code in 0 ..< 28 {
            let from = baseLength[code]
            let through = baseLength[code + 1]
            for length in from ..< through { table[length - minMatch] = UInt8(code) }
        }
        table[maxMatch - minMatch] = 28  // length 258 is code 285's zero-extra encoding
        return table
    }()

    /// The two-tier distance→code table: 256 exact entries for 1…256, then 256 entries indexed by
    /// `(distance − 1) >> 7` for 257…32768 (§3.2.5).
    private static let distanceCodeTable: [UInt8] = {
        var table = [UInt8](repeating: 0, count: 512)
        for code in 0 ..< 30 {
            let from = baseDistance[code]
            let through = code == 29 ? 32_769 : baseDistance[code + 1]
            for distance in from ..< through where distance <= 256 {
                table[distance - 1] = UInt8(code)
            }
            for distance in from ..< through where distance > 256 {
                table[256 + ((distance - 1) >> 7)] = UInt8(code)
            }
        }
        return table
    }()

    /// The distance code (0…29) for a match distance 1…32768 (§3.2.5).
    @inline(__always)
    static func distanceCode(_ distance: Int) -> Int {
        distance <= 256
            ? Int(distanceCodeTable[distance - 1])
            : Int(distanceCodeTable[256 + ((distance - 1) >> 7)])
    }

    /// The §3.2.6 fixed literal/length code lengths (8/9/7/8 across the four symbol bands).
    static let fixedLiteralLengths: [UInt8] = {
        var lengths = [UInt8](repeating: 8, count: 288)
        for symbol in 144 ... 255 { lengths[symbol] = 9 }
        for symbol in 256 ... 279 { lengths[symbol] = 7 }
        return lengths
    }()

    /// The §3.2.6 fixed literal/length codes, bit-reversed for the LSB-first writer.
    static let fixedLiteralCodes: [UInt16] = {
        var codes = [UInt16](repeating: 0, count: 288)
        DeflateHuffman.assignCanonicalCodes(
            lengths: fixedLiteralLengths, count: 288, into: &codes
        )
        return codes
    }()

    /// The §3.2.6 fixed distance code lengths (30 five-bit codes).
    static let fixedDistanceLengths = [UInt8](repeating: 5, count: 30)

    /// The §3.2.6 fixed distance codes, bit-reversed for the LSB-first writer.
    static let fixedDistanceCodes: [UInt16] = {
        var codes = [UInt16](repeating: 0, count: 30)
        DeflateHuffman.assignCanonicalCodes(
            lengths: fixedDistanceLengths, count: 30, into: &codes
        )
        return codes
    }()

    /// Reverses the low `bits` bits of `code` — §3.1.1's MSB-first code packing, pre-applied.
    static func reverse(_ code: Int, _ bits: Int) -> Int {
        var input = code
        var output = 0
        for _ in 0 ..< bits {
            output = (output << 1) | (input & 1)
            input >>= 1
        }
        return output
    }
}
