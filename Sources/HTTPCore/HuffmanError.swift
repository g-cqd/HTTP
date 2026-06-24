//
//  HuffmanError.swift
//  HTTPCore
//
//  RFC 7541 §5.2 — the three decoding errors the canonical HTTP Huffman decoder fails closed on:
//  the EOS symbol appearing in the input, padding longer than 7 bits, and padding that is not all
//  1-bits.
//

/// An error decoding a Huffman-coded string (RFC 7541 §5.2).
public enum HuffmanError: Error, Sendable, Equatable {
    /// The encoded data decoded the `EOS` symbol, which MUST NOT appear in the input (§5.2).
    case eosInInput

    /// The trailing padding was longer than 7 bits, or was not the MSBs of `EOS` (all 1-bits) (§5.2).
    case invalidPadding

    /// The bit stream did not form any valid code within the maximum code length.
    case invalidCode
}
