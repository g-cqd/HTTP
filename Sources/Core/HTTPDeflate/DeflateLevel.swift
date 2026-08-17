//
//  DeflateLevel.swift
//  HTTPDeflate
//
//  The compressor's effort knob. Three grades, not zlib's ten: `store` (RFC 1951 §3.2.4 stored
//  blocks only — framing without compression), `fast` (greedy matching, short hash chains — zlib's
//  low levels), and `balanced` (lazy matching with zlib level-6's tuning — the default everywhere
//  a content coding compresses on the fly). Each grade fixes the match-finder parameters, so equal
//  input at equal level always yields equal output.
//

/// The compression effort grade (fixed match-finder tuning per grade).
public enum DeflateLevel: Sendable, Equatable {
    /// Stored blocks only — no matching, no Huffman coding. The cheapest valid DEFLATE stream.
    case store
    /// Greedy matching over short hash chains (zlib's fast levels): better ratio than `store` at a
    /// fraction of `balanced`'s CPU.
    case fast
    /// Lazy matching with zlib level-6 tuning — the ratio/CPU balance the content codings default to.
    case balanced

    /// The match the lazy evaluator accepts without trying to better it at the next position.
    @usableFromInline
    var maxLazy: Int {
        self == .balanced ? 16 : 0
    }

    /// A match this long stops the chain walk (zlib's `nice_length`).
    @usableFromInline
    var niceLength: Int {
        self == .balanced ? 128 : 16
    }

    /// The most hash-chain candidates examined per position (zlib's `max_chain`).
    @usableFromInline
    var maxChain: Int {
        self == .balanced ? 128 : 16
    }

    /// A current match at least this long halves the chain-walk budget (zlib's `good_length`).
    @usableFromInline
    var goodLength: Int {
        self == .balanced ? 8 : 4
    }
}
