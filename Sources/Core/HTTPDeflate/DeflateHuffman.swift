//
//  DeflateHuffman.swift
//  HTTPDeflate
//
//  RFC 1951 §3.2.1 / §3.2.2 — the compressor's length-limited canonical Huffman builder. Optimal
//  code lengths come from the classic two-queue merge over frequency-sorted leaves (iterative — no
//  heap, no recursion, fixed scratch); depths beyond the limit (15 for the symbol alphabets, 7 for
//  the code-length alphabet, §3.2.7) are repaired with zlib's length-count redistribution, which
//  preserves the Kraft equality the decoder's table builder demands. Codes are then assigned in the
//  §3.2.2 canonical order and stored bit-reversed for the LSB-first writer. All scratch is owned by
//  the instance, so per-block builds allocate nothing.
//

/// The length-limited canonical Huffman code builder (RFC 1951 §3.2.2), with owned scratch.
struct DeflateHuffman {
    /// The largest alphabet built (literal/length: 286 symbols → 571 tree nodes).
    private static let maxSymbols = 286

    /// Active symbols sorted by (frequency, symbol) — the deterministic tie-break.
    private var order = [Int32](repeating: 0, count: maxSymbols)
    /// Node frequencies: leaves `0 ..< active`, then internal nodes as created.
    private var nodeFrequency = [Int](repeating: 0, count: 2 * maxSymbols - 1)
    /// Each node's parent (set as the merge creates it).
    private var parent = [Int32](repeating: 0, count: 2 * maxSymbols - 1)
    /// Each node's depth, computed root-down after the merge.
    private var depth = [Int32](repeating: 0, count: 2 * maxSymbols - 1)
    /// Codes per length, 0…15 — shared by the limit repair and canonical assignment.
    private var lengthCounts = [Int](repeating: 0, count: 16)
    /// The §3.2.2 `next_code` register for canonical assignment.
    private var nextCode = [Int](repeating: 0, count: 16)

    /// Fills `lengths` with limit-bounded optimal code lengths for `frequencies` (0 = unused).
    mutating func buildLengths(
        frequencies: [Int], count: Int, limit: Int, into lengths: inout [UInt8]
    ) {
        for symbol in 0 ..< count { lengths[symbol] = 0 }
        var active = 0
        for symbol in 0 ..< count where frequencies[symbol] > 0 {
            order[active] = Int32(symbol)
            active += 1
        }
        guard active > 1 else {
            if active == 1 {
                lengths[Int(order[0])] = 1  // a single code is sent as one 1-bit code
            }
            return
        }
        sortActive(count: active, frequencies: frequencies)
        mergeTree(count: active, frequencies: frequencies)
        let overflow = countDepths(count: active, limit: limit)
        if overflow > 0 {
            repairOverflow(overflow: overflow, limit: limit)
        }
        assignLengths(limit: limit, into: &lengths)
    }

    /// Assigns canonical codes (bit-reversed for the LSB-first writer) from `lengths` (§3.2.2).
    mutating func assignCodes(lengths: [UInt8], count: Int, into codes: inout [UInt16]) {
        for bits in 0 ..< 16 { lengthCounts[bits] = 0 }
        for symbol in 0 ..< count { lengthCounts[Int(lengths[symbol])] += 1 }
        var code = 0
        lengthCounts[0] = 0
        for bits in 1 ..< 16 {
            code = (code + lengthCounts[bits - 1]) << 1
            nextCode[bits] = code
        }
        for symbol in 0 ..< count where lengths[symbol] != 0 {
            let bits = Int(lengths[symbol])
            codes[symbol] = UInt16(DeflateTables.reverse(nextCode[bits], bits))
            nextCode[bits] += 1
        }
    }

    /// The allocation-tolerant form for one-time static tables (the §3.2.6 fixed codes).
    static func assignCanonicalCodes(lengths: [UInt8], count: Int, into codes: inout [UInt16]) {
        var builder = Self()
        builder.assignCodes(lengths: lengths, count: count, into: &codes)
    }

    /// In-place heapsort of `order[0 ..< count]` by (frequency, symbol) — no allocation, no
    /// recursion, deterministic.
    private mutating func sortActive(count: Int, frequencies: [Int]) {
        var start = count / 2 - 1
        while start >= 0 {
            siftDown(from: start, count: count, frequencies: frequencies)
            start -= 1
        }
        var end = count - 1
        while end > 0 {
            order.swapAt(0, end)
            siftDown(from: 0, count: end, frequencies: frequencies)
            end -= 1
        }
    }

    /// One heapsort sift (max-heap on the (frequency, symbol) key).
    private mutating func siftDown(from start: Int, count: Int, frequencies: [Int]) {
        var root = start
        while true {
            var largest = root
            let left = 2 * root + 1
            let right = left + 1
            if left < count, keyLess(largest, left, frequencies) { largest = left }
            if right < count, keyLess(largest, right, frequencies) { largest = right }
            guard largest != root else {
                return
            }
            order.swapAt(root, largest)
            root = largest
        }
    }

    /// Compares two `order` slots by their (frequency, symbol) key.
    private func keyLess(_ a: Int, _ b: Int, _ frequencies: [Int]) -> Bool {
        let left = Int(order[a])
        let right = Int(order[b])
        return frequencies[left] < frequencies[right]
            || (frequencies[left] == frequencies[right] && left < right)
    }

    /// The two-queue Huffman merge: leaves ascending, internal nodes created in ascending
    /// frequency order, so two cursors replace a priority queue.
    private mutating func mergeTree(count: Int, frequencies: [Int]) {
        for leaf in 0 ..< count { nodeFrequency[leaf] = frequencies[Int(order[leaf])] }
        var leafCursor = 0
        var internalCursor = count
        var next = count
        while next < 2 * count - 1 {
            let first = popSmallest(&leafCursor, &internalCursor, leafLimit: count, made: next)
            let second = popSmallest(&leafCursor, &internalCursor, leafLimit: count, made: next)
            nodeFrequency[next] = nodeFrequency[first] + nodeFrequency[second]
            parent[first] = Int32(next)
            parent[second] = Int32(next)
            next += 1
        }
    }

    /// Pops the lower-frequency head of the two queues (leaves win ties — deterministic).
    private func popSmallest(
        _ leafCursor: inout Int, _ internalCursor: inout Int, leafLimit: Int, made: Int
    ) -> Int {
        let leafAvailable = leafCursor < leafLimit
        let internalAvailable = internalCursor < made
        let takeLeaf =
            leafAvailable
            && (!internalAvailable || nodeFrequency[leafCursor] <= nodeFrequency[internalCursor])
        if takeLeaf {
            leafCursor += 1
            return leafCursor - 1
        }
        internalCursor += 1
        return internalCursor - 1
    }

    /// Computes leaf depths root-down (parents are always created after children) and buckets them
    /// into ``lengthCounts``, clamping at `limit`; returns how many leaves overflowed.
    private mutating func countDepths(count: Int, limit: Int) -> Int {
        let root = 2 * count - 2
        depth[root] = 0
        var node = root - 1
        while node >= 0 {
            depth[node] = depth[Int(parent[node])] + 1
            node -= 1
        }
        for bits in 0 ..< 16 { lengthCounts[bits] = 0 }
        var overflow = 0
        for leaf in 0 ..< count {
            var bits = Int(depth[leaf])
            if bits > limit {
                bits = limit
                overflow += 1
            }
            lengthCounts[bits] += 1
        }
        return overflow
    }

    /// zlib's overflow repair: move leaves between length buckets until the Kraft equality holds
    /// again with no length past `limit`.
    private mutating func repairOverflow(overflow: Int, limit: Int) {
        var remaining = overflow
        while remaining > 0 {
            var bits = limit - 1
            while lengthCounts[bits] == 0 { bits -= 1 }
            lengthCounts[bits] -= 1
            lengthCounts[bits + 1] += 2
            lengthCounts[limit] -= 1
            remaining -= 2
        }
    }

    /// Hands the bucketed lengths back to symbols: deepest lengths to the least frequent (the
    /// frequency-ascending ``order``), preserving optimal shape.
    private mutating func assignLengths(limit: Int, into lengths: inout [UInt8]) {
        var leaf = 0
        var bits = limit
        while bits >= 1 {
            var remaining = lengthCounts[bits]
            while remaining > 0 {
                lengths[Int(order[leaf])] = UInt8(bits)
                leaf += 1
                remaining -= 1
            }
            bits -= 1
        }
    }
}
