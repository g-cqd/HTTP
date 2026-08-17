//
//  Inflator.swift
//  HTTPDeflate
//
//  RFC 1951 — the raw DEFLATE decompressor, sans-I/O: push a `Span` of coded octets, pull inflated
//  octets into an `OutputSpan`, suspend losslessly at any input or output boundary. This is the
//  attacker-facing half of the codec, so every malformed shape is a typed ``InflateError`` (never a
//  trap), memory is fixed at init (32 KiB window + the two proven-bound decode tables; zero
//  steady-state allocation), and every loop is iterative. The 32 KiB sliding window persists across
//  ``run`` calls — and across sync-flushed segments — which is exactly the context-takeover behavior
//  RFC 7692 §7.2.2 needs; ``reset()`` clears it for `no_context_takeover`.
//
//  The state machine (one case per RFC 1951 §3.2.3–§3.2.7 phase) lives here; the dynamic-header
//  phases are in Inflator+DynamicHeader.swift and the symbol hot loop in Inflator+Symbols.swift.
//

/// The sans-I/O raw-DEFLATE (RFC 1951) decompressor: `Span` in, `OutputSpan` out, typed errors.
public struct Inflator {
    /// The DEFLATE history window size — `2^15` octets (RFC 1951 §3.2.1's maximum distance).
    static let windowSize = 32_768
    /// The index mask of the ring the window is kept in.
    static let windowMask = windowSize - 1

    /// One phase of RFC 1951 §3.2 block decoding; each case names the RFC field it is waiting on.
    enum State {
        /// Reading BFINAL + BTYPE (§3.2.3).
        case blockHeader
        /// Byte-aligning, then reading a stored block's LEN/NLEN (§3.2.4).
        case storedLength
        /// Copying a stored block's octets through (§3.2.4).
        case storedCopy(remaining: Int)
        /// Reading HLIT/HDIST/HCLEN (§3.2.7).
        case tableCounts
        /// Reading the code-length code's 3-bit lengths (§3.2.7).
        case codeLengthCodes
        /// Reading the literal/length + distance code lengths via the code-length code (§3.2.7).
        case codeLengths
        /// Decoding a literal/length symbol (§3.2.5).
        case symbols
        /// Decoding the distance of a match whose length is known (§3.2.5).
        case distance(length: Int)
        /// Copying a resolved match out of the window (§3.2.5).
        case copy(remaining: Int, distance: Int)
        /// The final (BFINAL) block is complete; unconsumed input belongs to the caller.
        case finished

        /// Whether this phase is handled inside the symbol hot loop.
        var isSymbolPhase: Bool {
            switch self {
                case .symbols, .distance, .copy:
                    true
                default:
                    false
            }
        }
    }

    /// How one phase step left the machine: advanced to another phase, or stalled on a boundary.
    enum Step {
        /// The phase completed; dispatch the next one.
        case advanced
        /// Out of input or output (or the stream finished); surface `CodecProgress` to the caller.
        case stall(CodecProgress)
    }

    /// The current §3.2 phase.
    var state: State = .blockHeader
    /// Whether the current block carried BFINAL (§3.2.3).
    var lastBlock = false

    /// The LSB-first bit accumulator (§3.1.1): up to 64 bits, low bit = next bit of the stream.
    var bitBuffer: UInt64 = 0
    /// How many low bits of ``bitBuffer`` are real.
    var bitCount = 0

    /// The 32 KiB history ring every output octet is folded into (§3.2.1 back-references).
    var window = [UInt8](repeating: 0, count: windowSize)
    /// The ring's next write position.
    var windowIndex = 0
    /// Total octets inflated since init/reset — bounds valid back-reference distances.
    var totalWritten = 0

    /// Decode-table storage: literal/length at 0, distance at ``InflateTable/enoughLengths``.
    var tables = [UInt32](
        repeating: 0, count: InflateTable.enoughLengths + InflateTable.enoughDistances
    )
    /// The table builder's reusable workspace.
    var scratch = InflateTable.Scratch()
    /// Code lengths being collected: the 19 code-length codes, then up to 286 + 30 symbol lengths.
    var lengths = [UInt8](repeating: 0, count: 320)

    /// HLIT + 257 (§3.2.7).
    var literalCount = 0
    /// HDIST + 1 (§3.2.7).
    var distanceCount = 0
    /// HCLEN + 4 (§3.2.7).
    var codeLengthCount = 0
    /// The resume cursor of whichever header loop is in progress.
    var headerIndex = 0
    /// Root index widths of the three live tables.
    var codeLengthRoot = 0
    var literalRoot = 0
    var distanceRoot = 0

    /// Creates a decompressor positioned before the first block.
    public init() {
        // All storage is fixed here; `run` never allocates.
    }

    /// Forgets all history and framing state — the RFC 7692 §7.1.1 `no_context_takeover` reset.
    ///
    /// The window contents need no wipe: `totalWritten = 0` makes every distance into the stale
    /// region invalid (``InflateError/distanceTooFar``) before it can be read.
    public mutating func reset() {
        state = .blockHeader
        lastBlock = false
        bitBuffer = 0
        bitCount = 0
        windowIndex = 0
        totalWritten = 0
    }

    /// Decompresses as much as possible: consumes `input` from `inputIndex`, appends to `output`.
    ///
    /// - Parameters:
    ///   - input: The coded octets. Any suffix of a stream is fine — the machine suspends and
    ///     resumes losslessly at arbitrary boundaries.
    ///   - inputIndex: The read cursor, advanced past every consumed octet. When the stream
    ///     finishes, whole unconsumed octets buffered ahead are given back (the cursor then points
    ///     at the first octet after the stream, e.g. a gzip trailer).
    ///   - output: The destination; the machine appends until it stalls or the stream ends.
    /// - Returns: ``CodecProgress/needsInput``, ``CodecProgress/needsOutput``, or
    ///   ``CodecProgress/finished`` once the BFINAL block completes.
    /// - Throws: ``InflateError`` on any malformed shape — the machine is then poisoned and the
    ///   caller discards it (fail closed).
    public mutating func run(
        input: Span<UInt8>, from inputIndex: inout Int, into output: inout OutputSpan<UInt8>
    ) throws(InflateError) -> CodecProgress {
        while true {
            let step: Step
            switch state {
                case .blockHeader:
                    step = try readBlockHeader(input, &inputIndex)
                case .storedLength:
                    step = try readStoredLength(input, &inputIndex)
                case .storedCopy:
                    step = copyStored(input, &inputIndex, into: &output)
                case .tableCounts:
                    step = try readTableCounts(input, &inputIndex)
                case .codeLengthCodes:
                    step = try readCodeLengthCodes(input, &inputIndex)
                case .codeLengths:
                    step = try readCodeLengths(input, &inputIndex)
                case .symbols, .distance, .copy:
                    step = try decodeSymbols(input, &inputIndex, into: &output)
                case .finished:
                    return .finished
            }
            if case .stall(let progress) = step {
                return progress
            }
        }
    }

    // MARK: Bits (RFC 1951 §3.1.1 — LSB-first packing)

    /// Tops the bit accumulator up from `input` (never leaves fewer than 57 bits while input lasts).
    @inline(__always)
    mutating func refill(_ input: Span<UInt8>, _ index: inout Int) {
        while bitCount <= 56, index < input.count {
            bitBuffer |= UInt64(input[index]) << UInt64(bitCount)
            index += 1
            bitCount += 8
        }
    }

    /// Whether `count` real bits are buffered.
    @inline(__always)
    func hasBits(_ count: Int) -> Bool {
        bitCount >= count
    }

    /// Consumes `count` bits and returns them (low bit first).
    @inline(__always)
    mutating func take(_ count: Int) -> Int {
        let value = Int(bitBuffer & ((UInt64(1) << UInt64(count)) - 1))
        bitBuffer >>= UInt64(count)
        bitCount -= count
        return value
    }

    /// Drops bits up to the next byte boundary (§3.2.4's stored-block alignment); idempotent.
    @inline(__always)
    mutating func alignToByte() {
        let drop = bitCount & 7
        bitBuffer >>= UInt64(drop)
        bitCount -= drop
    }

    /// Returns whole buffered-but-unused octets to the caller's cursor at stream end.
    @inline(__always)
    mutating func giveBackUnusedBytes(_ index: inout Int) {
        index -= bitCount >> 3
        bitBuffer = 0
        bitCount = 0
    }

    // MARK: Output (window-folded)

    /// Appends one octet to `output` and folds it into the history window.
    @inline(__always)
    mutating func write(_ byte: UInt8, into output: inout OutputSpan<UInt8>) {
        output.append(byte)
        window[windowIndex] = byte
        windowIndex = (windowIndex + 1) & Self.windowMask
        totalWritten += 1
    }

    // MARK: Block framing (RFC 1951 §3.2.3 / §3.2.4)

    /// Reads BFINAL + BTYPE and dispatches the block (§3.2.3).
    mutating func readBlockHeader(
        _ input: Span<UInt8>, _ index: inout Int
    ) throws(InflateError) -> Step {
        refill(input, &index)
        guard hasBits(3) else {
            return .stall(.needsInput)
        }
        lastBlock = take(1) == 1
        switch take(2) {
            case 0:
                state = .storedLength
            case 1:
                installFixedTables()
                state = .symbols
            case 2:
                state = .tableCounts
            default:
                throw .invalidBlockType  // BTYPE 11 is reserved (§3.2.3)
        }
        return .advanced
    }

    /// Aligns to a byte boundary and reads a stored block's LEN/NLEN (§3.2.4).
    mutating func readStoredLength(
        _ input: Span<UInt8>, _ index: inout Int
    ) throws(InflateError) -> Step {
        alignToByte()
        refill(input, &index)
        guard hasBits(32) else {
            return .stall(.needsInput)
        }
        let length = take(16)
        guard take(16) == length ^ 0xFFFF else {
            throw .invalidStoredLength  // NLEN must be LEN's one's complement (§3.2.4)
        }
        state = .storedCopy(remaining: length)
        return .advanced
    }

    /// Copies a stored block through, octet for octet (§3.2.4).
    mutating func copyStored(
        _ input: Span<UInt8>, _ index: inout Int, into output: inout OutputSpan<UInt8>
    ) -> Step {
        guard case .storedCopy(var remaining) = state else {
            return .advanced
        }
        while remaining > 0 {
            guard output.freeCapacity > 0 else {
                state = .storedCopy(remaining: remaining)
                return .stall(.needsOutput)
            }
            let byte: UInt8
            if bitCount >= 8 {
                byte = UInt8(take(8))
            }
            else if index < input.count {
                byte = input[index]
                index += 1
            }
            else {
                state = .storedCopy(remaining: remaining)
                return .stall(.needsInput)
            }
            write(byte, into: &output)
            remaining -= 1
        }
        return endBlock(&index)
    }

    /// Ends the current block: back to the next header, or — after BFINAL — the finished state,
    /// giving buffered whole octets back to the caller (§3.2.3).
    mutating func endBlock(_ index: inout Int) -> Step {
        guard lastBlock else {
            state = .blockHeader
            return .advanced
        }
        giveBackUnusedBytes(&index)
        state = .finished
        return .advanced
    }
}
