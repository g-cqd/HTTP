//
//  InflateError.swift
//  HTTPDeflate
//
//  The typed failure set of the attacker-facing half. Every way a DEFLATE stream (RFC 1951) or its
//  gzip (RFC 1952) / zlib (RFC 1950) envelope can be malformed maps to one case here — never a trap,
//  never unbounded memory, exactly the fail-closed contract the decompression middleware (CWE-409)
//  and the WebSocket inflater (RFC 7692 §7.2.2) rely on.
//

/// A malformed DEFLATE stream or container envelope (fail-closed; RFC section per case).
public enum InflateError: Error, Sendable, Equatable {
    /// A block declared the reserved type `BTYPE == 11` (RFC 1951 §3.2.3).
    case invalidBlockType
    /// A stored block's `NLEN` is not the one's complement of `LEN` (RFC 1951 §3.2.4).
    case invalidStoredLength
    /// A dynamic header's `HLIT`/`HDIST` exceed 286/30 code counts (RFC 1951 §3.2.7).
    case invalidCodeCounts
    /// A code-length alphabet that is over-subscribed or incomplete (RFC 1951 §3.2.7).
    case invalidCodeLengthCode
    /// A repeat instruction (symbols 16–18) with no previous length or overrunning the count
    /// (RFC 1951 §3.2.7).
    case invalidRepeat
    /// A literal/length alphabet that is over-subscribed or incomplete (RFC 1951 §3.2.2/§3.2.7).
    case invalidLiteralLengthCode
    /// A distance alphabet that is over-subscribed or incomplete (RFC 1951 §3.2.2/§3.2.7).
    case invalidDistanceCode
    /// A decoded symbol outside its alphabet — a reserved literal/length (286–287) or distance
    /// (30–31) code (RFC 1951 §3.2.5/§3.2.6).
    case invalidSymbol
    /// A back-reference reaching before the start of the output (RFC 1951 §3.2.5).
    case distanceTooFar
    /// A gzip member whose magic, method, or reserved flag bits are wrong (RFC 1952 §2.3).
    case invalidGzipHeader
    /// A gzip `FHCRC` header checksum that does not match (RFC 1952 §2.3.1).
    case headerChecksumMismatch
    /// A gzip trailer CRC-32 that does not match the inflated octets (RFC 1952 §2.3.1).
    case checksumMismatch
    /// A gzip trailer `ISIZE` that does not match the inflated length mod 2³² (RFC 1952 §2.3.1).
    case sizeMismatch
    /// A zlib envelope with a bad check value, window size, method, or a preset dictionary —
    /// `FDICT` is unsupported on this server-side path (RFC 1950 §2.2).
    case invalidZlibHeader
    /// A zlib Adler-32 trailer that does not match the inflated octets (RFC 1950 §2.2).
    case adlerMismatch
}
