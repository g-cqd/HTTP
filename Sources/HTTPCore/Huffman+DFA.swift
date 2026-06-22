//
//  Huffman+DFA.swift
//  HTTPCore
//
//  RFC 7541 §5.2 — a nibble (4-bit) finite-state machine for Huffman decoding, generated once from
//  the Appendix B code table. Decoding consumes four bits per table lookup (two lookups per input
//  octet) instead of walking one bit at a time. Because the shortest code is five bits, four bits can
//  complete at most one code, so each transition emits at most one symbol. Iterative; no recursion.
//

extension Huffman {

    /// One nibble transition: the resulting state, an optionally-emitted symbol, and status flags.
    @usableFromInline
    struct NibbleTransition: Sendable {
        let nextState: UInt16
        let symbol: UInt8
        let flags: UInt8
    }

    /// This nibble completed a literal symbol (``NibbleTransition/symbol`` is valid).
    @usableFromInline static let emitFlag: UInt8 = 1
    /// This nibble entered the EOS code — it MUST NOT appear in the input (RFC 7541 §5.2).
    @usableFromInline static let eosFlag: UInt8 = 2
    /// This nibble left the code tree — an undecodable bit sequence (RFC 7541 §5.2).
    @usableFromInline static let invalidFlag: UInt8 = 4

    /// The generated nibble decoder: the transition table plus the per-state padding-validity vector.
    @usableFromInline
    struct NibbleDFA: Sendable {
        /// Transitions indexed `state * 16 + nibble` (high nibble of an octet first).
        let transitions: [NibbleTransition]
        /// Whether ending in a state is valid trailing padding: the root, or a ≤ 7-bit all-ones EOS
        /// prefix (RFC 7541 §5.2).
        let paddingValid: [Bool]
    }

    /// The nibble decode FSM, built once from ``codes`` / ``lengths`` (thread-safe lazy `static let`).
    @usableFromInline
    static let nibbleDFA: NibbleDFA = buildNibbleDFA()

    private static func buildNibbleDFA() -> NibbleDFA {
        // 1. Build the canonical binary code tree. Node 0 is the root; `children[node][bit]` is a child
        //    index or -1, and `symbol[node]` is the decoded value at a leaf (256 == EOS).
        var children: [[Int]] = [[-1, -1]]
        var symbol: [Int?] = [nil]
        var depth = [0]
        var allOnes = [true]  // is the root→node path made only of 1-bits? (the root, vacuously)
        for value in codes.indices {
            let code = codes[value]
            var node = 0
            for position in stride(from: Int(lengths[value]) - 1, through: 0, by: -1) {
                let bit = Int((code >> position) & 1)
                if children[node][bit] == -1 {
                    children.append([-1, -1])
                    symbol.append(nil)
                    depth.append(depth[node] + 1)
                    allOnes.append(allOnes[node] && bit == 1)
                    children[node][bit] = children.count - 1
                }
                node = children[node][bit]
            }
            symbol[node] = value
        }

        // 2. For every internal node (a possible state) and every 4-bit nibble, walk the four bits —
        //    emitting a symbol and resetting to the root on a leaf — to record the resulting state,
        //    emission, and any §5.2 error.
        let stateCount = children.count
        var transitions = [NibbleTransition](
            repeating: NibbleTransition(nextState: 0, symbol: 0, flags: 0), count: stateCount * 16)
        for state in 0..<stateCount where symbol[state] == nil {  // leaves are never start states
            for nibble in 0..<16 {
                var node = state
                var emitted: Int?
                var flags: UInt8 = 0
                for position in stride(from: 3, through: 0, by: -1) {
                    let next = children[node][(nibble >> position) & 1]
                    if next == -1 {
                        flags |= invalidFlag
                        break
                    }
                    node = next
                    if let leaf = symbol[node] {
                        if leaf == Int(eosSymbol) {
                            flags |= eosFlag
                            break
                        }
                        emitted = leaf
                        // Reset to the root for the remaining bits (≤ 1 emission per nibble).
                        node = 0
                    }
                }
                if emitted != nil { flags |= emitFlag }
                transitions[state * 16 + nibble] = NibbleTransition(
                    nextState: UInt16(node), symbol: UInt8(emitted ?? 0), flags: flags)
            }
        }

        // 3. A decode may legally end only at the root or on a ≤ 7-bit all-ones EOS prefix (§5.2).
        let paddingValid = (0..<stateCount).map { allOnes[$0] && depth[$0] <= 7 }
        return NibbleDFA(transitions: transitions, paddingValid: paddingValid)
    }
}
