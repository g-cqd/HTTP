//
//  Inflator+DynamicHeader.swift
//  HTTPDeflate
//
//  RFC 1951 §3.2.7 — the dynamic-Huffman block header: HLIT/HDIST/HCLEN, the permuted 3-bit
//  code-length-code lengths, the run-length-coded literal/length + distance code lengths (symbols
//  16/17/18), and the table builds; plus the §3.2.6 fixed tables, built once and installed by copy.
//  Every phase suspends losslessly on input exhaustion and fails closed on the §3.2.7 error shapes:
//  out-of-range counts, an unusable code-length code, repeat overruns, and over-subscribed or
//  incomplete symbol alphabets.
//

extension Inflator {
    /// The §3.2.7 permutation in which the code-length code's lengths arrive.
    static let codeLengthOrder: [Int] = [
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15
    ]

    /// The §3.2.6 fixed tables, built once: literal/length (root 9, 512 entries) then the 32-entry
    /// distance table (root 5).
    static let fixedTables: [UInt32] = {
        var table = [UInt32](repeating: 0, count: 512 + 32)
        var lengths = [UInt8](repeating: 8, count: 288)
        for symbol in 144 ... 255 { lengths[symbol] = 9 }
        for symbol in 256 ... 279 { lengths[symbol] = 7 }
        var scratch = InflateTable.Scratch()
        _ = InflateTable.build(
            .literalsAndLengths,
            lengths: lengths,
            lengthsBase: 0,
            codes: 288,
            rootBits: 9,
            into: &table,
            base: 0,
            scratch: &scratch
        )
        let distances = [UInt8](repeating: 5, count: 32)
        _ = InflateTable.build(
            .distances,
            lengths: distances,
            lengthsBase: 0,
            codes: 32,
            rootBits: 5,
            into: &table,
            base: 512,
            scratch: &scratch
        )
        return table
    }()

    /// Installs the fixed tables (§3.2.6) into the live table storage.
    mutating func installFixedTables() {
        let fixed = Self.fixedTables
        for index in 0 ..< 512 { tables[index] = fixed[index] }
        for index in 0 ..< 32 { tables[InflateTable.enoughLengths + index] = fixed[512 + index] }
        literalRoot = 9
        distanceRoot = 5
    }

    /// Reads HLIT/HDIST/HCLEN and range-checks them (§3.2.7).
    mutating func readTableCounts(
        _ input: Span<UInt8>, _ index: inout Int
    ) throws(InflateError) -> Step {
        refill(input, &index)
        guard hasBits(14) else {
            return .stall(.needsInput)
        }
        literalCount = take(5) + 257
        distanceCount = take(5) + 1
        codeLengthCount = take(4) + 4
        guard literalCount <= 286, distanceCount <= 30 else {
            throw .invalidCodeCounts  // §3.2.7: 286/30 are the alphabet maxima
        }
        headerIndex = 0
        for position in 0 ..< 19 { lengths[position] = 0 }
        state = .codeLengthCodes
        return .advanced
    }

    /// Reads the `HCLEN + 4` permuted 3-bit code-length-code lengths and builds their table (§3.2.7).
    mutating func readCodeLengthCodes(
        _ input: Span<UInt8>, _ index: inout Int
    ) throws(InflateError) -> Step {
        while headerIndex < codeLengthCount {
            refill(input, &index)
            guard hasBits(3) else {
                return .stall(.needsInput)
            }
            lengths[Self.codeLengthOrder[headerIndex]] = UInt8(take(3))
            headerIndex += 1
        }
        guard
            let root = InflateTable.build(
                .codeLengths,
                lengths: lengths,
                lengthsBase: 0,
                codes: 19,
                rootBits: 7,
                into: &tables,
                base: 0,
                scratch: &scratch
            )
        else {
            throw .invalidCodeLengthCode  // over-subscribed or incomplete (§3.2.7)
        }
        codeLengthRoot = root
        headerIndex = 0
        state = .codeLengths
        return .advanced
    }

    /// Reads the `HLIT + HDIST` symbol code lengths through the code-length code, expanding the
    /// 16/17/18 repeats, then builds both symbol tables (§3.2.7).
    mutating func readCodeLengths(
        _ input: Span<UInt8>, _ index: inout Int
    ) throws(InflateError) -> Step {
        let total = literalCount + distanceCount
        while headerIndex < total {
            guard
                let (_, symbol, bits) = decodeEntry(
                    input, &index, base: 0, rootBits: codeLengthRoot
                )
            else {
                return .stall(.needsInput)
            }
            if symbol < 16 {
                _ = take(bits)
                lengths[headerIndex] = UInt8(symbol)
                headerIndex += 1
                continue
            }
            if case .stall(let progress) = try expandRepeat(symbol: symbol, codeBits: bits) {
                return .stall(progress)
            }
        }
        try buildSymbolTables()
        state = .symbols
        return .advanced
    }

    /// Expands one repeat symbol (16 = copy previous ×3–6, 17 = zero ×3–10, 18 = zero ×11–138),
    /// consuming its code and extra bits atomically (§3.2.7).
    private mutating func expandRepeat(
        symbol: Int, codeBits: Int
    ) throws(InflateError) -> Step {
        let extra = symbol == 16 ? 2 : (symbol == 17 ? 3 : 7)
        guard hasBits(codeBits + extra) else {
            return .stall(.needsInput)  // nothing consumed; the phase re-decodes on resume
        }
        _ = take(codeBits)
        let value: UInt8
        let repeats: Int
        switch symbol {
            case 16:
                guard headerIndex > 0 else {
                    throw .invalidRepeat  // no previous length to copy (§3.2.7)
                }
                value = lengths[headerIndex - 1]
                repeats = 3 + take(2)
            case 17:
                value = 0
                repeats = 3 + take(3)
            default:
                value = 0
                repeats = 11 + take(7)
        }
        guard headerIndex + repeats <= literalCount + distanceCount else {
            throw .invalidRepeat  // repeat runs past the declared symbol count (§3.2.7)
        }
        for offset in 0 ..< repeats { lengths[headerIndex + offset] = value }
        headerIndex += repeats
        return .advanced
    }

    /// Builds the literal/length (root 9) and distance (root 6) tables from the collected lengths.
    private mutating func buildSymbolTables() throws(InflateError) {
        guard lengths[256] != 0 else {
            throw .invalidLiteralLengthCode  // a block with no end-of-block code cannot terminate
        }
        guard
            let literal = InflateTable.build(
                .literalsAndLengths,
                lengths: lengths,
                lengthsBase: 0,
                codes: literalCount,
                rootBits: 9,
                into: &tables,
                base: 0,
                scratch: &scratch
            )
        else {
            throw .invalidLiteralLengthCode
        }
        literalRoot = literal
        guard
            let distance = InflateTable.build(
                .distances,
                lengths: lengths,
                lengthsBase: literalCount,
                codes: distanceCount,
                rootBits: 6,
                into: &tables,
                base: InflateTable.enoughLengths,
                scratch: &scratch
            )
        else {
            throw .invalidDistanceCode
        }
        distanceRoot = distance
    }
}
