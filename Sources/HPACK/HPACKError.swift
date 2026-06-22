//
//  HPACKError.swift
//  HPACK
//
//  RFC 7541 — typed HPACK encoding/decoding errors. A decoding error is fatal to the whole HTTP/2
//  connection (a COMPRESSION_ERROR, RFC 9113 §4.3), because the dynamic table would otherwise fall
//  out of sync — so each case names a precise, fail-closed cause.
//

/// An HPACK encoding or decoding error (RFC 7541).
public enum HPACKError: Error, Sendable, Equatable {

    /// The octet stream ended in the middle of a prefix integer (RFC 7541 §5.1).
    case truncatedInteger

    /// A prefix integer exceeded the decoder's bound — an overflow / oversized-length attack (§5.1).
    case integerOverflow

    /// The octet stream ended before a string literal's declared length (RFC 7541 §5.2).
    case truncatedString

    /// A string literal's declared length exceeded the configured maximum — oversized-field abuse.
    case stringTooLong

    /// A Huffman-coded string failed to decode: EOS in input, bad padding, or an invalid code (§5.2).
    case invalidHuffman
}
