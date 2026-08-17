//
//  Inflator+Symbols.swift
//  HTTPDeflate
//
//  RFC 1951 §3.2.5 — the symbol hot loop: literal/length decode, distance decode, and the window
//  copy, driven through the two-level tables (root lookup + at most one bounded sub-table lookup —
//  see InflateTable.swift). Kept in this one extension so a later tuned variant (SSE2/AVX2/NEON
//  behind runtime dispatch — the multi-arch policy's Phase 4 candidate) replaces exactly one loop.
//  Each phase consumes its code and extra bits atomically, so a stall on either boundary is lossless
//  and resuming re-decodes from unconsumed bits.
//

extension Inflator {
    /// Decodes one canonical code without consuming bits: root lookup, then the sub-table hop for
    /// codes longer than the root (§3.2.2).
    ///
    /// Accepts an entry only once the buffered bit count covers its full code length — safe because
    /// canonical replication makes every index sharing those low bits map to the same entry.
    ///
    /// - Returns: The resolved `(op, value, bits)` (bits = full code length to consume), or nil when
    ///   the input is exhausted before a whole code is visible.
    @inline(__always)
    mutating func decodeEntry(
        _ input: Span<UInt8>, _ index: inout Int, base: Int, rootBits: Int
    ) -> (op: Int, value: Int, bits: Int)? {
        while true {
            refill(input, &index)
            let root = tables[base + Int(bitBuffer & ((UInt64(1) << UInt64(rootBits)) - 1))]
            var op = Int(root & 0xFF)
            var bits = Int((root >> 8) & 0xFF)
            var value = Int(root >> 16)
            if op != 0, op < 16 {
                // Link: `op` is the sub-table's index width, `value` its offset past `base`.
                let shifted = bitBuffer >> UInt64(rootBits)
                let sub = tables[base + value + Int(shifted & ((UInt64(1) << UInt64(op)) - 1))]
                op = Int(sub & 0xFF)
                bits = rootBits + Int((sub >> 8) & 0xFF)
                value = Int(sub >> 16)
            }
            if bits <= bitCount {
                return (op, value, bits)
            }
            guard index < input.count else {
                return nil
            }
        }
    }

    /// The symbol hot loop: dispatches the three §3.2.5 phases until a boundary stalls it or the
    /// block ends.
    mutating func decodeSymbols(
        _ input: Span<UInt8>, _ index: inout Int, into output: inout OutputSpan<UInt8>
    ) throws(InflateError) -> Step {
        while true {
            let step: Step
            switch state {
                case .symbols:
                    step = try decodeLiteralOrLength(input, &index, into: &output)
                case .distance(let length):
                    step = try decodeDistance(length: length, input, &index)
                case .copy(let remaining, let distance):
                    step = copyMatch(remaining: remaining, distance: distance, into: &output)
                default:
                    return .advanced  // the block ended; `run` dispatches the next phase
            }
            if case .stall = step {
                return step
            }
            if !state.isSymbolPhase {
                return .advanced
            }
        }
    }

    /// Decodes one literal/length symbol: a literal octet, a match length (base + extra bits), or
    /// the end-of-block symbol (§3.2.5).
    @inline(__always)
    private mutating func decodeLiteralOrLength(
        _ input: Span<UInt8>, _ index: inout Int, into output: inout OutputSpan<UInt8>
    ) throws(InflateError) -> Step {
        guard
            let (op, value, bits) = decodeEntry(input, &index, base: 0, rootBits: literalRoot)
        else {
            return .stall(.needsInput)
        }
        if op == 0 {
            guard output.freeCapacity > 0 else {
                return .stall(.needsOutput)
            }
            _ = take(bits)
            write(UInt8(value), into: &output)
            return .advanced
        }
        if op & 16 != 0 {
            let extra = op & 15
            guard hasBits(bits + extra) else {
                return .stall(.needsInput)
            }
            _ = take(bits)
            state = .distance(length: value + take(extra))
            return .advanced
        }
        if op & 32 != 0 {
            _ = take(bits)
            return endBlock(&index)  // end-of-block symbol 256 (§3.2.5)
        }
        throw .invalidSymbol  // reserved literal/length codes 286/287 (§3.2.5)
    }

    /// Decodes the distance of the pending match: code + extra bits, then validates the
    /// back-reference against what has actually been written (§3.2.5).
    @inline(__always)
    private mutating func decodeDistance(
        length: Int, _ input: Span<UInt8>, _ index: inout Int
    ) throws(InflateError) -> Step {
        guard
            let (op, value, bits) = decodeEntry(
                input, &index, base: InflateTable.enoughLengths, rootBits: distanceRoot
            )
        else {
            return .stall(.needsInput)
        }
        guard op & 64 == 0, op & 16 != 0 else {
            throw .invalidSymbol  // reserved distance codes 30/31 (§3.2.5)
        }
        let extra = op & 15
        guard hasBits(bits + extra) else {
            return .stall(.needsInput)
        }
        _ = take(bits)
        let distance = value + take(extra)
        guard distance <= totalWritten else {
            throw .distanceTooFar  // reaches before the start of the output (§3.2.5)
        }
        state = .copy(remaining: length, distance: distance)
        return .advanced
    }

    /// Copies the resolved match out of the history window, one octet at a time — correct for
    /// overlapping copies (the distance-1 run idiom of §3.2.5) by construction.
    @inline(__always)
    private mutating func copyMatch(
        remaining: Int, distance: Int, into output: inout OutputSpan<UInt8>
    ) -> Step {
        var left = remaining
        while left > 0 {
            guard output.freeCapacity > 0 else {
                state = .copy(remaining: left, distance: distance)
                return .stall(.needsOutput)
            }
            let byte = window[(windowIndex - distance) & Self.windowMask]
            write(byte, into: &output)
            left -= 1
        }
        state = .symbols
        return .advanced
    }
}
