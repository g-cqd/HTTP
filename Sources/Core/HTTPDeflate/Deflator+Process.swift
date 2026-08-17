//
//  Deflator+Process.swift
//  HTTPDeflate
//
//  RFC 1951 §4 — the level-specific process loops: pass-through for `.store`, greedy hash-chain
//  matching for `.fast`, and zlib deflate_slow's lazy evaluation for `.balanced` (defer a match one
//  position to see if a longer one starts at the next octet). Matching only runs with a full
//  lookahead (262 octets) visible unless a flush is armed — the structural source of
//  chunk-stability — and the hash-chain walk is plain portable Swift, shaped so a tuned SIMD
//  comparator can replace `matchLength(at:cap:)` behind runtime dispatch later (multi-arch policy,
//  Phase 4).
//

extension Deflator {
    /// Compresses whatever the lookahead allows; true when a block was emitted (drain before
    /// more). `draining` is true only when a flush is armed AND every input octet is buffered —
    /// the only condition under which the sub-lookahead tail may be processed.
    mutating func compressAvailable(draining: Bool) -> Bool {
        switch level {
            case .store:
                processStore()
            case .fast:
                processGreedy(draining: draining)
            case .balanced:
                processLazy(draining: draining)
        }
    }

    /// Whether the match loops may take another step (full lookahead, or the drain takes the tail).
    private func shouldProcess(draining: Bool) -> Bool {
        lookahead >= Self.minLookahead || (draining && lookahead > 0)
    }

    /// A block flush is due: the symbol buffer is full or the block hit its input-octet limit.
    private func blockNeedsFlush() -> Bool {
        block.isFull || cursor - blockStart >= Self.blockByteLimit
    }

    // MARK: `.store` — stored blocks only (§3.2.4)

    /// Advances the cursor without matching; emits a stored block at every ``blockByteLimit``.
    private mutating func processStore() -> Bool {
        while lookahead > 0 {
            let room = Self.blockByteLimit - (cursor - blockStart)
            let advance = min(room, lookahead)
            cursor += advance
            lookahead -= advance
            if cursor - blockStart >= Self.blockByteLimit {
                emitBlock(last: false)
                return true
            }
        }
        return false
    }

    // MARK: `.fast` — greedy matching (zlib deflate_fast)

    /// Takes the first acceptable match at each position.
    private mutating func processGreedy(draining: Bool) -> Bool {
        while shouldProcess(draining: draining) {
            var candidate = 0
            if lookahead >= DeflateTables.minMatch {
                candidate = insertString(at: cursor)
            }
            var length = 0
            var start = 0
            if candidate != 0, cursor - candidate <= Self.maxDistance {
                (length, start) = longestMatch(
                    candidate: candidate, priorLength: DeflateTables.minMatch - 1
                )
            }
            if length >= DeflateTables.minMatch {
                acceptGreedyMatch(length: length, start: start)
            }
            else {
                block.tallyLiteral(window[cursor])
                cursor += 1
                lookahead -= 1
            }
            if blockNeedsFlush() {
                emitBlock(last: false)
                return true
            }
        }
        return false
    }

    /// Tallies a greedy match and advances over it, inserting the covered positions.
    private mutating func acceptGreedyMatch(length: Int, start: Int) {
        block.tallyMatch(length: length, distance: cursor - start)
        let maxInsert = cursor + lookahead - DeflateTables.minMatch
        var position = cursor + 1
        let end = cursor + length
        while position < end {
            if position <= maxInsert {
                _ = insertString(at: position)
            }
            position += 1
        }
        cursor = end
        lookahead -= length
    }

    // MARK: `.balanced` — lazy matching (zlib deflate_slow)

    /// Defers each match one position: emit the previous match only if the current position does
    /// not start a longer one.
    private mutating func processLazy(draining: Bool) -> Bool {
        while shouldProcess(draining: draining) {
            if lazyStep() {
                return true
            }
        }
        if draining, lookahead == 0, literalPending {
            // The deferred literal at the very end of the stream (zlib's flush-tail case).
            block.tallyLiteral(window[cursor - 1])
            literalPending = false
            if blockNeedsFlush() {
                emitBlock(last: false)
                return true
            }
        }
        return false
    }

    /// One lazy-evaluation step; true when it flushed a block.
    private mutating func lazyStep() -> Bool {
        var candidate = 0
        if lookahead >= DeflateTables.minMatch {
            candidate = insertString(at: cursor)
        }
        pendingLength = currentLength
        pendingStart = currentStart
        currentLength = DeflateTables.minMatch - 1
        if candidate != 0, pendingLength < level.maxLazy, cursor - candidate <= Self.maxDistance {
            evaluateCandidate(candidate)
        }
        if pendingLength >= DeflateTables.minMatch, currentLength <= pendingLength {
            acceptPendingMatch()
            // The tallied symbols cover exactly [blockStart, cursor) here — the only points a
            // block may be cut (zlib's FLUSH_BLOCK invariant; a cut elsewhere would strand the
            // deferred octet between the stored range and the symbol stream).
            if blockNeedsFlush() {
                emitBlock(last: false)
                return true
            }
            return false
        }
        if literalPending {
            block.tallyLiteral(window[cursor - 1])
            // Covered == cursor here (the octet at cursor itself is still deferred), so the cut
            // must happen BEFORE advancing — mirroring zlib's flush-then-increment order.
            let flushed = blockNeedsFlush()
            if flushed {
                emitBlock(last: false)
            }
            cursor += 1
            lookahead -= 1
            return flushed
        }
        literalPending = true
        cursor += 1
        lookahead -= 1
        return false  // nothing tallied — covered < cursor, so no cut is legal here
    }

    /// Searches the chain at the cursor, recording a match only if it beats the deferred one; a
    /// minimal match too far back is not worth its distance code (zlib's `TOO_FAR`).
    private mutating func evaluateCandidate(_ candidate: Int) {
        let (length, start) = longestMatch(candidate: candidate, priorLength: pendingLength)
        currentLength = length
        currentStart = start
        if currentLength == DeflateTables.minMatch, cursor - currentStart > Self.tooFar {
            currentLength = DeflateTables.minMatch - 1
        }
    }

    /// Emits the deferred match (it starts at `cursor − 1`) and advances over its remainder,
    /// inserting the covered positions.
    private mutating func acceptPendingMatch() {
        let maxInsert = cursor + lookahead - DeflateTables.minMatch
        block.tallyMatch(length: pendingLength, distance: cursor - 1 - pendingStart)
        lookahead -= pendingLength - 1
        var remaining = pendingLength - 2
        while remaining > 0 {
            cursor += 1
            if cursor <= maxInsert {
                _ = insertString(at: cursor)
            }
            remaining -= 1
        }
        literalPending = false
        currentLength = DeflateTables.minMatch - 1
        cursor += 1
    }

    // MARK: The chain walk

    /// Walks the hash chain for the longest match at the cursor that beats `priorLength`.
    ///
    /// Distance-limited to ``maxDistance``, effort-limited by the level's chain budget (quartered
    /// once a good deferred match exists), and capped to the real lookahead so a flush-tail match
    /// never reads past the buffered input.
    func longestMatch(candidate: Int, priorLength: Int) -> (length: Int, start: Int) {
        var chainBudget = level.maxChain
        if priorLength >= level.goodLength {
            chainBudget >>= 2
        }
        let maxLength = min(DeflateTables.maxMatch, lookahead)
        let nice = min(level.niceLength, lookahead)
        let limit = cursor > Self.maxDistance ? cursor - Self.maxDistance : 0
        var best = priorLength
        var bestStart = 0
        var current = candidate
        while current > limit, chainBudget > 0 {
            chainBudget -= 1
            if best < maxLength, window[current + best] == window[cursor + best],
                window[current] == window[cursor]
            {
                let length = matchLength(at: current, cap: maxLength)
                if length > best {
                    best = length
                    bestStart = current
                    if length >= nice {
                        break
                    }
                }
            }
            current = Int(chain[current & Self.windowMask])
        }
        return (best, bestStart)
    }

    /// The plain forward comparator — the one function a tuned SIMD variant would replace.
    private func matchLength(at position: Int, cap: Int) -> Int {
        var length = 0
        while length < cap, window[position + length] == window[cursor + length] {
            length += 1
        }
        return length
    }
}
