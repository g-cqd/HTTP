//
//  InflateTable.swift
//  HTTPDeflate
//
//  RFC 1951 §3.2.2 — canonical Huffman decode tables, in the classic two-level (root + linked
//  sub-table) layout: one root lookup of `rootBits` bits resolves short codes directly and long codes
//  through a second bounded lookup, so the decoder's inner loop is two array reads worst-case. The
//  construction is a faithful port of the proven table builder from zlib's inftrees.c (the canonical
//  code enumeration of RFC 1951 §3.2.2): it walks codes in (length, symbol) order, replicates entries
//  across the unused low index bits, and sizes each sub-table to exactly cover its prefix.
//  Over-subscribed sets are rejected outright; incomplete sets are rejected except the single
//  1-bit-code case the ecosystem (zlib) accepts for the literal/length and distance alphabets.
//  Iterative; no recursion; the caller owns all storage, so steady-state builds allocate nothing.
//
//  Entry packing (32 bits): `op | bits << 8 | val << 16`, with zlib's op semantics —
//    op == 0          literal, `val` is the octet
//    op & 16          base value `val` plus `op & 15` extra bits (length or distance)
//    1 ≤ op ≤ 15      link to a sub-table of `op` index bits at `val` entries past the table base
//    op & 32          end of block
//    op & 64 (no 32)  invalid code (reserved symbol, or the unused space of an accepted
//                     single-code alphabet)
//

/// The two-level canonical Huffman decode-table builder (RFC 1951 §3.2.2; ports zlib's inftrees.c).
enum InflateTable {
    /// The most entries a literal/length table can need (zlib's proven `ENOUGH_LENS` bound).
    static let enoughLengths = 852
    /// The most entries a distance table can need (zlib's proven `ENOUGH_DISTS` bound).
    static let enoughDistances = 592
    /// The longest DEFLATE code, in bits (RFC 1951 §3.2.1).
    static let maxBits = 15

    /// Which of the three DEFLATE alphabets a table decodes (RFC 1951 §3.2.5–§3.2.7).
    enum Kind {
        /// The code-length alphabet of a dynamic header (§3.2.7) — incomplete sets rejected.
        case codeLengths
        /// The literal/length alphabet (§3.2.5).
        case literalsAndLengths
        /// The distance alphabet (§3.2.5).
        case distances

        /// The proven entry bound for this alphabet's table.
        var capacity: Int {
            switch self {
                case .codeLengths:
                    128  // complete ≤7-bit codes fit the 128-entry root exactly
                case .literalsAndLengths:
                    enoughLengths
                case .distances:
                    enoughDistances
            }
        }
    }

    /// Length-code bases for symbols 257…285, then two zeros for the reserved 286/287 (§3.2.5).
    private static let lengthBase: [UInt16] = [
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
        35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258, 0, 0
    ]

    /// Length-code ops for 257…285 (`16 | extra bits`), then invalid markers for 286/287.
    private static let lengthOp: [UInt16] = [
        16, 16, 16, 16, 16, 16, 16, 16, 17, 17, 17, 17, 18, 18, 18, 18,
        19, 19, 19, 19, 20, 20, 20, 20, 21, 21, 21, 21, 16, 77, 202
    ]

    /// Distance-code bases for symbols 0…29, then two zeros for the reserved 30/31 (§3.2.5).
    private static let distanceBase: [UInt16] = [
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
        257, 385, 513, 769, 1_025, 1_537, 2_049, 3_073, 4_097, 6_145,
        8_193, 12_289, 16_385, 24_577, 0, 0
    ]

    /// Distance-code ops for 0…29 (`16 | extra bits`), then invalid markers for 30/31.
    private static let distanceOp: [UInt16] = [
        16, 16, 16, 16, 17, 17, 18, 18, 19, 19, 20, 20, 21, 21, 22, 22,
        23, 23, 24, 24, 25, 25, 26, 26, 27, 27, 28, 28, 29, 29, 64, 64
    ]

    /// Packs one decode entry: `op | bits << 8 | val << 16`.
    @inline(__always)
    static func entry(op: Int, bits: Int, value: Int) -> UInt32 {
        UInt32(op) | (UInt32(bits) << 8) | (UInt32(value) << 16)
    }

    /// The builder's reusable workspace, owned by the decoder so steady-state builds allocate nothing.
    struct Scratch {
        /// Symbols sorted by (length, symbol) — up to the 288 literal/length codes.
        var work = [UInt16](repeating: 0, count: 288)
        /// Codes per length 0…15.
        var counts = [Int](repeating: 0, count: maxBits + 1)
        /// Per-length write offsets for the counting sort.
        var offsets = [Int](repeating: 0, count: maxBits + 1)
    }

    /// Builds the decode table for `kind` from `codes` code lengths.
    ///
    /// - Parameters:
    ///   - kind: The alphabet the table decodes.
    ///   - lengths: The per-symbol code lengths (0 = unused), read at `lengthsBase ..< lengthsBase +
    ///     codes`.
    ///   - lengthsBase: The first index of this alphabet's lengths within `lengths`.
    ///   - codes: The number of symbols.
    ///   - rootBits: The requested root-table index width (clamped to the actual code lengths).
    ///   - table: The backing storage entries are written into.
    ///   - base: The first index in `table` this table may use.
    ///   - scratch: The builder's reusable counters and sorted-symbol workspace.
    /// - Returns: The root index width actually used, or nil for an over-subscribed / (disallowed)
    ///   incomplete set or a table that would overrun its proven bound.
    static func build(
        _ kind: Kind,
        lengths: [UInt8],
        lengthsBase: Int,
        codes: Int,
        rootBits: Int,
        into table: inout [UInt32],
        base: Int,
        scratch: inout Scratch
    ) -> Int? {
        for length in 0 ... maxBits { scratch.counts[length] = 0 }
        for symbol in 0 ..< codes {
            scratch.counts[Int(lengths[lengthsBase + symbol])] += 1
        }
        var max = maxBits
        while max >= 1, scratch.counts[max] == 0 { max -= 1 }
        if max == 0 {
            // No symbols at all: two 1-bit invalid entries force the error at first use, which is
            // how an empty distance alphabet (legal until referenced) is represented.
            table[base] = entry(op: 64, bits: 1, value: 0)
            table[base + 1] = table[base]
            return 1
        }
        var min = 1
        while min < max, scratch.counts[min] == 0 { min += 1 }
        guard kraftAllows(counts: scratch.counts, max: max, kind: kind) else {
            return nil
        }
        sortSymbols(lengths: lengths, lengthsBase: lengthsBase, codes: codes, scratch: &scratch)
        var filler = Filler(
            kind: kind,
            min: min,
            max: max,
            rootBits: Swift.max(Swift.min(rootBits, max), min),
            base: base
        )
        return filler.fill(
            lengths: lengths,
            lengthsBase: lengthsBase,
            into: &table,
            scratch: &scratch
        )
    }

    /// Checks the Kraft sum: rejects over-subscribed sets always, and incomplete sets except the
    /// single 1-bit code zlib accepts for the literal/length and distance alphabets (§3.2.7).
    private static func kraftAllows(counts: [Int], max: Int, kind: Kind) -> Bool {
        var left = 1
        for length in 1 ... maxBits {
            left <<= 1
            left -= counts[length]
            if left < 0 {
                return false  // over-subscribed
            }
        }
        if left > 0, kind == .codeLengths || max != 1 {
            return false  // incomplete (allowed only as one 1-bit code outside the header alphabet)
        }
        return true
    }

    /// Sorts symbols into `scratch.work` by (code length, symbol) — the canonical order (§3.2.2).
    private static func sortSymbols(
        lengths: [UInt8], lengthsBase: Int, codes: Int, scratch: inout Scratch
    ) {
        scratch.offsets[1] = 0
        for length in 1 ..< maxBits {
            scratch.offsets[length + 1] = scratch.offsets[length] + scratch.counts[length]
        }
        for symbol in 0 ..< codes where lengths[lengthsBase + symbol] != 0 {
            let length = Int(lengths[lengthsBase + symbol])
            scratch.work[scratch.offsets[length]] = UInt16(symbol)
            scratch.offsets[length] += 1
        }
    }

    /// The main enumeration/fill pass — zlib inftrees.c's loop as a small mutable machine.
    private struct Filler {
        let kind: Kind
        let min: Int
        let max: Int
        let rootBits: Int
        let base: Int

        /// The canonical code being enumerated (bit-reversed convention of RFC 1951 §3.1.1).
        private var huff = 0
        /// Index bits resolved by the root before a sub-table lookup (0 while filling the root).
        private var drop = 0
        /// The current (sub-)table's absolute start.
        private var next = 0
        /// The size of the table currently being filled, and the total entries committed.
        private var currentSize = 0
        private var used = 0
        /// The root index of the sub-table being filled (−1 while filling the root).
        private var low = -1

        init(kind: Kind, min: Int, max: Int, rootBits: Int, base: Int) {
            self.kind = kind
            self.min = min
            self.max = max
            self.rootBits = rootBits
            self.base = base
            next = base
            currentSize = 1 << rootBits
            used = 1 << rootBits
        }

        /// Runs the enumeration; returns the root width used, or nil past the capacity bound.
        mutating func fill(
            lengths: [UInt8],
            lengthsBase: Int,
            into table: inout [UInt32],
            scratch: inout InflateTable.Scratch
        ) -> Int? {
            guard used <= kind.capacity else {
                return nil
            }
            var symbolIndex = 0
            var length = min
            while true {
                replicate(
                    entryFor(symbol: Int(scratch.work[symbolIndex]), bits: length - drop),
                    length: length,
                    into: &table
                )
                incrementCode(length: length)
                symbolIndex += 1
                scratch.counts[length] -= 1
                if scratch.counts[length] == 0 {
                    if length == max { break }
                    length = Int(lengths[lengthsBase + Int(scratch.work[symbolIndex])])
                }
                if length > rootBits, huff & ((1 << rootBits) - 1) != low {
                    guard startSubTable(length: length, into: &table, scratch: scratch) else {
                        return nil
                    }
                }
            }
            if huff != 0 {
                // The accepted-incomplete case leaves exactly one open slot; make it invalid.
                table[next + (huff >> drop)] = entry(op: 64, bits: length - drop, value: 0)
            }
            return rootBits
        }

        /// The packed entry for one symbol of the current alphabet.
        private func entryFor(symbol: Int, bits: Int) -> UInt32 {
            switch kind {
                case .codeLengths:
                    entry(op: 0, bits: bits, value: symbol)
                case .literalsAndLengths:
                    if symbol < 256 {
                        entry(op: 0, bits: bits, value: symbol)
                    }
                    else if symbol > 256 {
                        entry(
                            op: Int(lengthOp[symbol - 257]),
                            bits: bits,
                            value: Int(lengthBase[symbol - 257])
                        )
                    }
                    else {
                        entry(op: 32 + 64, bits: bits, value: 0)  // end of block (§3.2.5)
                    }
                case .distances:
                    entry(op: Int(distanceOp[symbol]), bits: bits, value: Int(distanceBase[symbol]))
            }
        }

        /// Writes `value` at every index of the current table whose low `length − drop` bits match
        /// the current code (the canonical replication of §3.2.2).
        private func replicate(_ value: UInt32, length: Int, into table: inout [UInt32]) {
            let increment = 1 << (length - drop)
            var position = currentSize
            repeat {
                position -= increment
                table[next + (huff >> drop) + position] = value
            } while position != 0
        }

        /// Advances `huff` to the next canonical code of `length` bits (bit-reversed increment).
        private mutating func incrementCode(length: Int) {
            var increment = 1 << (length - 1)
            while increment != 0, huff & increment != 0 { increment >>= 1 }
            huff = increment != 0 ? (huff & (increment - 1)) + increment : 0
        }

        /// Opens the sub-table for the prefix at `huff`, sized to cover its remaining codes, and
        /// links it from the root; false when it would overrun the alphabet's proven bound.
        private mutating func startSubTable(
            length: Int, into table: inout [UInt32], scratch: InflateTable.Scratch
        ) -> Bool {
            if drop == 0 { drop = rootBits }
            next += currentSize
            var bits = length - drop
            var left = 1 << bits
            while bits + drop < max {
                left -= scratch.counts[bits + drop]
                if left <= 0 { break }
                bits += 1
                left <<= 1
            }
            currentSize = 1 << bits
            used += currentSize
            guard used <= kind.capacity else {
                return false
            }
            low = huff & ((1 << rootBits) - 1)
            table[base + low] = entry(op: bits, bits: rootBits, value: next - base)
            return true
        }
    }
}
