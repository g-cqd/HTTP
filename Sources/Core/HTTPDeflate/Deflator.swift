//
//  Deflator.swift
//  HTTPDeflate
//
//  RFC 1951 — the raw DEFLATE compressor, sans-I/O: push a `Span` of plain octets, pull coded
//  octets into an `OutputSpan`, request boundaries through ``DeflateFlush``. Input is buffered into
//  a 64 KiB sliding window and only compressed once a full lookahead (262 octets) is visible — or a
//  flush is armed — so under ``DeflateFlush/none`` the output is a function of the input octets
//  alone, never of their chunking (the byte-identity property the streamed/buffered content codings
//  pin). All storage is fixed at init; the steady state allocates nothing.
//
//  Blocks flush when the symbol buffer fills or the block reaches ``blockByteLimit`` input octets —
//  a limit chosen so the block's octets are ALWAYS still in the window when it is priced (the
//  stored representation never goes missing, unlike zlib's negative-`block_start` case), and small
//  enough that one block always fits the writer's fixed pending buffer.
//
//  The window/flush interplay lives here; the level-specific match loops are in
//  Deflator+Process.swift and block emission in DeflateBlockEncoder.swift.
//

/// The sans-I/O raw-DEFLATE (RFC 1951) compressor: `Span` in, `OutputSpan` out, flush on request.
public struct Deflator {
    /// The DEFLATE history window — `2^15` octets (RFC 1951 §3.2.1).
    static let windowSize = 32_768
    /// The ring mask for hash-chain positions.
    static let windowMask = windowSize - 1
    /// The full buffering window: history + lookahead (zlib's `2 * wSize` layout).
    static let totalWindow = 2 * windowSize
    /// The lookahead below which matching defers to keep chunking invisible
    /// (`maxMatch + minMatch + 1`, zlib's `MIN_LOOKAHEAD`).
    static let minLookahead = DeflateTables.maxMatch + DeflateTables.minMatch + 1
    /// The farthest usable match distance (`windowSize − minLookahead`, zlib's `MAX_DIST`).
    static let maxDistance = windowSize - minLookahead
    /// The 3-octet hash table size (15 bits, zlib's memLevel-8 shape).
    static let hashSize = 32_768
    static let hashMask = hashSize - 1
    /// Input octets per block before a forced flush — sized so a block never outlives the window
    /// (see the file header) and a stored block never exceeds §3.2.4's 65 535-octet LEN.
    static let blockByteLimit = 32_000
    /// A 3-octet match this far back is not worth its distance code (zlib's `TOO_FAR`).
    static let tooFar = 4_096

    /// The effort grade fixed at init.
    let level: DeflateLevel

    /// History + lookahead octets (`0 ..< cursor` is history, `cursor ..< cursor + lookahead` is
    /// buffered input).
    var window = [UInt8](repeating: 0, count: totalWindow)
    /// Hash → most recent window position of that 3-octet prefix (0 doubles as "none", zlib-style).
    var head = [UInt16](repeating: 0, count: hashSize)
    /// Per-position previous chain link (indexed by position & ``windowMask``).
    var chain = [UInt16](repeating: 0, count: windowSize)
    /// The compression cursor (zlib's `strstart`).
    var cursor = 0
    /// Buffered-but-uncompressed octets ahead of ``cursor``.
    var lookahead = 0
    /// Where the current block's input began in the window.
    var blockStart = 0

    /// The lazy evaluator's registers (zlib's `match_*`/`prev_*` state).
    var currentLength = DeflateTables.minMatch - 1
    var currentStart = 0
    var pendingLength = 0
    var pendingStart = 0
    var literalPending = false

    /// The block encoder and the bit writer it emits through.
    var block = DeflateBlockEncoder()
    var writer = DeflateBitWriter(capacity: 1 << 17)

    /// The armed flush (see ``run(input:from:into:flush:)``) and the sealed-stream latch.
    var pendingFlush: DeflateFlush = .none
    var finishedStream = false

    /// Creates a compressor at `level`, positioned at an empty stream.
    ///
    /// - Parameter level: The effort grade (fixed for the stream's lifetime).
    public init(level: DeflateLevel = .balanced) {
        self.level = level
    }

    /// Forgets all history and framing — the RFC 7692 §7.1.1 `no_context_takeover` reset.
    public mutating func reset() {
        for index in 0 ..< Self.hashSize { head[index] = 0 }
        cursor = 0
        lookahead = 0
        blockStart = 0
        currentLength = DeflateTables.minMatch - 1
        currentStart = 0
        pendingLength = 0
        pendingStart = 0
        literalPending = false
        writer.reset()
        pendingFlush = .none
        finishedStream = false
    }

    /// Compresses as much as possible: consumes `input` from `inputIndex`, appends to `output`.
    ///
    /// A non-`none` `flush` arms a boundary the machine then works toward across calls (keep
    /// passing it while draining): ``DeflateFlush/sync`` completes with the `00 00 FF FF`-tailed
    /// empty stored block, ``DeflateFlush/finish`` seals the stream. ``CodecProgress/needsInput``
    /// means everything requested so far — input, blocks, and any armed flush — is fully in
    /// `output`.
    ///
    /// - Parameters:
    ///   - input: The plain octets to compress (any chunking; see the chunk-stability note above).
    ///   - inputIndex: The read cursor, advanced past every consumed octet.
    ///   - output: The destination for coded octets.
    ///   - flush: The boundary to arm, if any.
    /// - Returns: ``CodecProgress/needsOutput`` when `output` filled up,
    ///   ``CodecProgress/needsInput`` when fully caught up, or ``CodecProgress/finished`` once a
    ///   `finish` flush has been fully drained (the stream is then sealed).
    public mutating func run(
        input: Span<UInt8>,
        from inputIndex: inout Int,
        into output: inout OutputSpan<UInt8>,
        flush: DeflateFlush = .none
    ) -> CodecProgress {
        if flush == .finish {
            pendingFlush = .finish
        }
        else if flush == .sync, pendingFlush == .none {
            pendingFlush = .sync
        }
        while true {
            guard writer.drain(into: &output) else {
                return .needsOutput
            }
            if finishedStream {
                return .finished
            }
            fillWindow(input, &inputIndex)
            // The armed flush may only drain the sub-lookahead tail once EVERY input octet is
            // buffered — otherwise a one-shot (input + finish in one call) would cut differently
            // than the same octets streamed, breaking chunk-stable byte-identity.
            let draining = pendingFlush != .none && inputIndex == input.count
            if compressAvailable(draining: draining) {
                continue  // a block was emitted — drain it before compressing more
            }
            if inputIndex < input.count {
                continue  // the window was full; compressing/sliding just made room
            }
            switch pendingFlush {
                case .none:
                    return .needsInput
                case .sync:
                    if !block.isEmpty || cursor > blockStart {
                        emitBlock(last: false)  // `cursor > blockStart` covers `.store`'s tail
                    }
                    writeSyncMarker()
                    pendingFlush = .none
                case .finish:
                    emitBlock(last: true)
                    writer.alignToByte()
                    finishedStream = true
            }
        }
    }

    /// Copies input into the window's free tail, sliding the window when it is safe and needed.
    mutating func fillWindow(_ input: Span<UInt8>, _ index: inout Int) {
        while index < input.count {
            var filled = cursor + lookahead
            if filled == Self.totalWindow {
                guard cursor >= Self.windowSize + Self.maxDistance else {
                    return  // no room and not yet slidable — compress first
                }
                slide()
                filled -= Self.windowSize
            }
            let take = min(Self.totalWindow - filled, input.count - index)
            for offset in 0 ..< take {
                window[filled + offset] = input[index + offset]
            }
            index += take
            lookahead += take
        }
    }

    /// Slides the window down by 32 KiB, rebasing every position (zlib's `fill_window` slide).
    mutating func slide() {
        for index in 0 ..< Self.windowSize {
            window[index] = window[index + Self.windowSize]
        }
        cursor -= Self.windowSize
        blockStart -= Self.windowSize
        currentStart -= Self.windowSize
        pendingStart -= Self.windowSize
        for index in 0 ..< Self.hashSize {
            let position = Int(head[index])
            head[index] = position >= Self.windowSize ? UInt16(position - Self.windowSize) : 0
        }
        for index in 0 ..< Self.windowSize {
            let position = Int(chain[index])
            chain[index] = position >= Self.windowSize ? UInt16(position - Self.windowSize) : 0
        }
    }

    /// Emits the pending block — stored-only at ``DeflateLevel/store``, cheapest-of-three
    /// otherwise — and starts the next one at the cursor.
    mutating func emitBlock(last: Bool) {
        if level == .store {
            block.emitStored(
                window: window, range: blockStart ..< cursor, last: last, into: &writer
            )
        }
        else {
            block.emit(
                last: last, window: window, storedRange: blockStart ..< cursor, into: &writer
            )
        }
        blockStart = cursor
    }

    /// Writes the RFC 7692 §7.2.1 sync boundary: an empty stored block, landing the stream on a
    /// byte boundary with the `00 00 FF FF` tail.
    mutating func writeSyncMarker() {
        writer.writeBits(0, 3)  // BFINAL 0, BTYPE 00
        writer.alignToByte()
        writer.writeLittleEndian16(0)
        writer.writeLittleEndian16(0xFFFF)
    }

    /// The 3-octet position hash (zlib's rolled `h << 5 ^ c` over a 15-bit table, unrolled).
    @inline(__always)
    func hash(at position: Int) -> Int {
        let first = Int(window[position]) << 10
        let second = Int(window[position + 1]) << 5
        return (first ^ second ^ Int(window[position + 2])) & Self.hashMask
    }

    /// Links `position` into its hash chain; returns the previous chain head (0 = none).
    @inline(__always)
    mutating func insertString(at position: Int) -> Int {
        let slot = hash(at: position)
        let previous = Int(head[slot])
        chain[position & Self.windowMask] = head[slot]
        head[slot] = UInt16(position)
        return previous
    }
}
