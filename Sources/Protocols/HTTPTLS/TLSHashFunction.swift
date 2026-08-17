//
//  TLSHashFunction.swift
//  HTTPTLS
//
//  RFC 8446 §7.1 — the hash a cipher suite names for its HKDF and transcript. TLS 1.3 uses
//  exactly two (SHA-256 and SHA-384, both from swift-crypto), so a two-case enum dispatches the
//  generic swift-crypto entry points and keeps every key-schedule type runtime-parameterized by
//  suite without generics bubbling through the whole module.
//

public import Crypto

/// The HKDF/transcript hash of a TLS 1.3 cipher suite (RFC 8446 §7.1): SHA-256 or SHA-384.
public enum TLSHashFunction: Sendable, Equatable {
    /// SHA-256 (`TLS_AES_128_GCM_SHA256`, `TLS_CHACHA20_POLY1305_SHA256`).
    case sha256
    /// SHA-384 (`TLS_AES_256_GCM_SHA384`).
    case sha384

    /// The digest length in octets (`Hash.length` throughout RFC 8446 §7.1).
    public var digestByteCount: Int {
        switch self {
            case .sha256:
                SHA256.byteCount
            case .sha384:
                SHA384.byteCount
        }
    }

    /// A `Hash.length`-octet all-zero key — §7.1's `0` input to `HKDF-Extract` when no PSK or
    /// ECDHE secret feeds a stage.
    public var zeroKey: SymmetricKey {
        SymmetricKey(data: [UInt8](repeating: 0, count: digestByteCount))
    }

    /// The digest of the empty string — `Transcript-Hash("")`, the §7.1 context of every
    /// `Derive-Secret` whose `Messages` argument is empty.
    public var emptyTranscriptHash: [UInt8] {
        switch self {
            case .sha256:
                Array(SHA256.hash(data: [UInt8]()))
            case .sha384:
                Array(SHA384.hash(data: [UInt8]()))
        }
    }
}
