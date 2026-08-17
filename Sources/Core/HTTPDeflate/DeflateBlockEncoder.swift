//
//  DeflateBlockEncoder.swift
//  HTTPDeflate
//
//  RFC 1951 §3.2.4–§3.2.7 — one block, end to end: the symbol buffer the match finder tallies into,
//  the per-block dynamic code construction, the run-length-coded code-length serialization (symbols
//  16/17/18), the exact bit-cost comparison of stored vs fixed vs dynamic, and the emission of the
//  cheapest. The block's input octets are always still in the compressor's window (the Deflator
//  flushes blocks well before a window slide could strand them), so the stored representation is
//  always available for incompressible data. All storage is fixed at init — per-block work
//  allocates nothing.
//
//  Symbols pack into one `UInt32`: a literal is the octet itself; a match is
//  `distance << 8 | (length − 3)` (distance ≥ 1 disambiguates).
//

/// One DEFLATE block: symbol accumulation, code construction, cost choice, and emission.
struct DeflateBlockEncoder {
    /// Symbols per block before a forced flush (zlib's memLevel-8 buffer).
    static let symbolCapacity = 16_384

    /// The packed literal/match symbols of the current block.
    private var symbols = [UInt32](repeating: 0, count: symbolCapacity)
    /// How many of ``symbols`` are live.
    private(set) var symbolCount = 0
    /// Literal/length symbol frequencies (285 max code; 256 = end-of-block).
    private var literalFrequency = [Int](repeating: 0, count: 286)
    /// Distance symbol frequencies.
    private var distanceFrequency = [Int](repeating: 0, count: 30)
    /// The dynamic literal/length code under construction.
    private var literalLengths = [UInt8](repeating: 0, count: 286)
    private var literalCodes = [UInt16](repeating: 0, count: 286)
    /// The dynamic distance code under construction.
    private var distanceLengths = [UInt8](repeating: 0, count: 30)
    private var distanceCodes = [UInt16](repeating: 0, count: 30)
    /// The code-length code (§3.2.7) under construction.
    private var codeLengthFrequency = [Int](repeating: 0, count: 19)
    private var codeLengthLengths = [UInt8](repeating: 0, count: 19)
    private var codeLengthCodes = [UInt16](repeating: 0, count: 19)
    /// The run-length-coded length sequence: `symbol | extraValue << 5` per entry (§3.2.7).
    private var runLength = [UInt16](repeating: 0, count: 286 + 30)
    private var runLengthCount = 0
    /// The length-limited Huffman builder (owned scratch).
    private var huffman = DeflateHuffman()

    /// Whether the symbol buffer forces a block flush.
    var isFull: Bool {
        symbolCount == Self.symbolCapacity
    }

    /// Whether the block holds no symbols.
    var isEmpty: Bool {
        symbolCount == 0
    }

    /// Tallies one literal octet (§3.2.5).
    mutating func tallyLiteral(_ byte: UInt8) {
        symbols[symbolCount] = UInt32(byte)
        symbolCount += 1
        literalFrequency[Int(byte)] += 1
    }

    /// Tallies one `<length, distance>` match (§3.2.5).
    mutating func tallyMatch(length: Int, distance: Int) {
        symbols[symbolCount] = UInt32(distance) << 8 | UInt32(length - DeflateTables.minMatch)
        symbolCount += 1
        literalFrequency[257 + Int(DeflateTables.lengthCode[length - DeflateTables.minMatch])] += 1
        distanceFrequency[DeflateTables.distanceCode(distance)] += 1
    }

    /// Emits the block as the cheapest of stored / fixed / dynamic, then resets for the next one.
    ///
    /// `storedRange` is the block's input octets inside `window` (always ≤ 65535 by the Deflator's
    /// flush rule, so a single stored block covers it).
    mutating func emit(
        last: Bool,
        window: [UInt8],
        storedRange: Range<Int>,
        into writer: inout DeflateBitWriter
    ) {
        let plan = planDynamic()
        let dynamicBits =
            3 + plan.headerBits
            + contentBits(literal: literalLengths, distance: distanceLengths)
        let fixedBits =
            3
            + contentBits(
                literal: DeflateTables.fixedLiteralLengths,
                distance: DeflateTables.fixedDistanceLengths
            )
        // Stored cost is exact except the ≤7 alignment bits, counted pessimistically.
        let storedBits = 3 + 7 + 32 + storedRange.count * 8
        if storedRange.count <= 65_535, storedBits <= min(dynamicBits, fixedBits) {
            emitStored(window: window, range: storedRange, last: last, into: &writer)
            return
        }
        writer.writeBits(last ? 1 : 0, 1)
        if fixedBits <= dynamicBits {
            writer.writeBits(1, 2)  // BTYPE 01 (§3.2.6)
            emitSymbols(
                literalCodes: DeflateTables.fixedLiteralCodes,
                literalLengths: DeflateTables.fixedLiteralLengths,
                distanceCodes: DeflateTables.fixedDistanceCodes,
                distanceLengths: DeflateTables.fixedDistanceLengths,
                into: &writer
            )
        }
        else {
            writer.writeBits(2, 2)  // BTYPE 10 (§3.2.7)
            emitDynamicHeader(plan, into: &writer)
            huffman.assignCodes(lengths: literalLengths, count: 286, into: &literalCodes)
            huffman.assignCodes(lengths: distanceLengths, count: 30, into: &distanceCodes)
            emitSymbols(
                literalCodes: literalCodes,
                literalLengths: literalLengths,
                distanceCodes: distanceCodes,
                distanceLengths: distanceLengths,
                into: &writer
            )
        }
        resetBlock()
    }

    /// Emits the block as a single stored block (§3.2.4) — also the `.store` level's direct path.
    mutating func emitStored(
        window: [UInt8],
        range: Range<Int>,
        last: Bool,
        into writer: inout DeflateBitWriter
    ) {
        writer.writeBits(last ? 1 : 0, 1)
        writer.writeBits(0, 2)  // BTYPE 00 (§3.2.4)
        writer.alignToByte()
        writer.writeLittleEndian16(range.count)
        writer.writeLittleEndian16(range.count ^ 0xFFFF)
        for index in range { writer.writeByte(window[index]) }
        resetBlock()
    }

    /// The dynamic header's derived shape: HLIT/HDIST/HCLEN and its exact bit cost (§3.2.7).
    private struct DynamicPlan {
        let literalCount: Int
        let distanceCount: Int
        let codeLengthCount: Int
        let headerBits: Int
    }

    /// Builds the dynamic codes and the run-length-coded length sequence; prices the header.
    private mutating func planDynamic() -> DynamicPlan {
        literalFrequency[256] = 1  // the end-of-block symbol is always sent (§3.2.5)
        huffman.buildLengths(
            frequencies: literalFrequency, count: 286, limit: 15, into: &literalLengths
        )
        huffman.buildLengths(
            frequencies: distanceFrequency, count: 30, limit: 15, into: &distanceLengths
        )
        let literalCount = max(257, highestUsed(literalLengths) + 1)
        let distanceCount = max(1, highestUsed(distanceLengths) + 1)
        buildRunLength(literalCount: literalCount, distanceCount: distanceCount)
        for symbol in 0 ..< 19 { codeLengthFrequency[symbol] = 0 }
        var extraBits = 0
        for index in 0 ..< runLengthCount {
            let symbol = Int(runLength[index]) & 31
            codeLengthFrequency[symbol] += 1
            extraBits += Self.repeatExtraBits(symbol)
        }
        huffman.buildLengths(
            frequencies: codeLengthFrequency, count: 19, limit: 7, into: &codeLengthLengths
        )
        var codeLengthCount = 19
        while codeLengthCount > 4,
            codeLengthLengths[Inflator.codeLengthOrder[codeLengthCount - 1]] == 0
        {
            codeLengthCount -= 1
        }
        var headerBits = 14 + codeLengthCount * 3 + extraBits
        for symbol in 0 ..< 19 {
            headerBits += codeLengthFrequency[symbol] * Int(codeLengthLengths[symbol])
        }
        return DynamicPlan(
            literalCount: literalCount,
            distanceCount: distanceCount,
            codeLengthCount: codeLengthCount,
            headerBits: headerBits
        )
    }

    /// Emits HLIT/HDIST/HCLEN, the permuted code-length-code lengths, and the RLE sequence (§3.2.7).
    private mutating func emitDynamicHeader(
        _ plan: DynamicPlan, into writer: inout DeflateBitWriter
    ) {
        writer.writeBits(plan.literalCount - 257, 5)
        writer.writeBits(plan.distanceCount - 1, 5)
        writer.writeBits(plan.codeLengthCount - 4, 4)
        for index in 0 ..< plan.codeLengthCount {
            writer.writeBits(Int(codeLengthLengths[Inflator.codeLengthOrder[index]]), 3)
        }
        huffman.assignCodes(lengths: codeLengthLengths, count: 19, into: &codeLengthCodes)
        for index in 0 ..< runLengthCount {
            let packed = Int(runLength[index])
            let symbol = packed & 31
            writer.writeBits(Int(codeLengthCodes[symbol]), Int(codeLengthLengths[symbol]))
            let extra = Self.repeatExtraBits(symbol)
            if extra > 0 {
                writer.writeBits(packed >> 5, extra)
            }
        }
    }

    /// Emits every tallied symbol, then the end-of-block code (§3.2.5).
    private mutating func emitSymbols(
        literalCodes: [UInt16],
        literalLengths: [UInt8],
        distanceCodes: [UInt16],
        distanceLengths: [UInt8],
        into writer: inout DeflateBitWriter
    ) {
        for index in 0 ..< symbolCount {
            let packed = symbols[index]
            let distance = Int(packed >> 8)
            if distance == 0 {
                let literal = Int(packed & 0xFF)
                writer.writeBits(Int(literalCodes[literal]), Int(literalLengths[literal]))
                continue
            }
            let length = Int(packed & 0xFF) + DeflateTables.minMatch
            let lengthIndex = Int(DeflateTables.lengthCode[length - DeflateTables.minMatch])
            let lengthSymbol = 257 + lengthIndex
            writer.writeBits(Int(literalCodes[lengthSymbol]), Int(literalLengths[lengthSymbol]))
            let lengthExtra = DeflateTables.extraLengthBits[lengthIndex]
            if lengthExtra > 0 {
                writer.writeBits(length - DeflateTables.baseLength[lengthIndex], lengthExtra)
            }
            let distanceIndex = DeflateTables.distanceCode(distance)
            writer.writeBits(Int(distanceCodes[distanceIndex]), Int(distanceLengths[distanceIndex]))
            let distanceExtra = DeflateTables.extraDistanceBits[distanceIndex]
            if distanceExtra > 0 {
                let base = DeflateTables.baseDistance[distanceIndex]
                writer.writeBits(distance - base, distanceExtra)
            }
        }
        writer.writeBits(Int(literalCodes[256]), Int(literalLengths[256]))
    }

    /// The exact content cost (symbols + extra bits + end-of-block) under the given code lengths.
    private func contentBits(literal: [UInt8], distance: [UInt8]) -> Int {
        var bits = 0
        for symbol in 0 ..< 286 where literalFrequency[symbol] > 0 {
            bits += literalFrequency[symbol] * Int(literal[symbol])
        }
        for index in 0 ..< 29 {
            bits += literalFrequency[257 + index] * DeflateTables.extraLengthBits[index]
        }
        for symbol in 0 ..< 30 where distanceFrequency[symbol] > 0 {
            bits +=
                distanceFrequency[symbol]
                * (Int(distance[symbol]) + DeflateTables.extraDistanceBits[symbol])
        }
        return bits
    }

    /// Run-length-codes the concatenated literal + distance length sequence (§3.2.7).
    private mutating func buildRunLength(literalCount: Int, distanceCount: Int) {
        runLengthCount = 0
        let total = literalCount + distanceCount
        var index = 0
        while index < total {
            let current = lengthAt(index, literalCount: literalCount)
            var run = 1
            while index + run < total,
                lengthAt(index + run, literalCount: literalCount) == current
            {
                run += 1
            }
            appendRun(value: current, run: run)
            index += run
        }
    }

    /// Appends one equal-length run as literals and 16/17/18 repeats (§3.2.7).
    private mutating func appendRun(value: Int, run: Int) {
        var remaining = run
        if value == 0 {
            while remaining >= 11 {
                let take = min(remaining, 138)
                appendRunSymbol(18, extraValue: take - 11)
                remaining -= take
            }
            if remaining >= 3 {
                appendRunSymbol(17, extraValue: remaining - 3)
                remaining = 0
            }
        }
        else {
            appendRunSymbol(value, extraValue: 0)
            remaining -= 1
            while remaining >= 3 {
                let take = min(remaining, 6)
                appendRunSymbol(16, extraValue: take - 3)
                remaining -= take
            }
        }
        while remaining > 0 {
            appendRunSymbol(value, extraValue: 0)
            remaining -= 1
        }
    }

    /// Appends one packed RLE entry.
    private mutating func appendRunSymbol(_ symbol: Int, extraValue: Int) {
        runLength[runLengthCount] = UInt16(symbol | (extraValue << 5))
        runLengthCount += 1
    }

    /// The concatenated length sequence the RLE walks (§3.2.7's joined alphabets).
    private func lengthAt(_ index: Int, literalCount: Int) -> Int {
        index < literalCount
            ? Int(literalLengths[index])
            : Int(distanceLengths[index - literalCount])
    }

    /// The extra-bit width of an RLE symbol (16 → 2, 17 → 3, 18 → 7).
    private static func repeatExtraBits(_ symbol: Int) -> Int {
        switch symbol {
            case 16:
                2
            case 17:
                3
            case 18:
                7
            default:
                0
        }
    }

    /// The highest symbol with a nonzero code length, or −1.
    private func highestUsed(_ lengths: [UInt8]) -> Int {
        var index = lengths.count - 1
        while index >= 0, lengths[index] == 0 { index -= 1 }
        return index
    }

    /// Clears the symbol buffer and frequencies for the next block.
    private mutating func resetBlock() {
        symbolCount = 0
        for symbol in 0 ..< 286 { literalFrequency[symbol] = 0 }
        for symbol in 0 ..< 30 { distanceFrequency[symbol] = 0 }
    }
}
