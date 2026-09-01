//
//  TLSCipherSuite.swift
//  HTTPTLS
//
//  RFC 8446 §B.4 — the TLS 1.3 cipher suites this server implements: the mandatory-to-implement
//  `TLS_AES_128_GCM_SHA256` (§9.1), plus `TLS_AES_256_GCM_SHA384` and
//  `TLS_CHACHA20_POLY1305_SHA256`. AEAD-only by construction — TLS 1.3 defines nothing else, and
//  every primitive is swift-crypto's. Each suite carries its §7.3 key geometry and its §5.5
//  protection limit so the record layer can drive KeyUpdate before any bound is at risk.
//

/// A TLS 1.3 cipher suite (RFC 8446 §B.4), with its key geometry and record limits.
public enum TLSCipherSuite: UInt16, Sendable, Equatable, CaseIterable {
    /// `TLS_AES_128_GCM_SHA256` — mandatory to implement (RFC 8446 §9.1).
    case aes128GcmSha256 = 0x1301
    /// `TLS_AES_256_GCM_SHA384` (RFC 8446 §B.4).
    case aes256GcmSha384 = 0x1302
    /// `TLS_CHACHA20_POLY1305_SHA256` (RFC 8446 §B.4).
    case chaCha20Poly1305Sha256 = 0x1303

    /// The suite's HKDF/transcript hash (RFC 8446 §7.1 — the suite names it).
    public var hash: TLSHashFunction {
        switch self {
            case .aes128GcmSha256, .chaCha20Poly1305Sha256:
                .sha256
            case .aes256GcmSha384:
                .sha384
        }
    }

    /// The AEAD key length in octets (§7.3: the length of the `"key"` expansion).
    public var keyLength: Int {
        switch self {
            case .aes128GcmSha256:
                16
            case .aes256GcmSha384, .chaCha20Poly1305Sha256:
                32
        }
    }

    /// The per-record nonce length in octets — 12 for all three AEADs (§5.3: `iv_length`).
    public var ivLength: Int {
        12
    }

    /// The AEAD tag length in octets — 16 for all three AEADs (§5.2's expansion).
    public var tagLength: Int {
        16
    }

    /// The §5.5 protection limit: how many records one key set may protect before KeyUpdate.
    ///
    /// AES-GCM's bound is "about 2^24.5 full-size records" — ⌊2^24.5⌋ here;
    /// ChaCha20-Poly1305's §5.5 limit exceeds the sequence-number space, so for it the hard
    /// 2^64 − 1 sequence bound (never wrapped — ``TLSRecordError/recordLimitReached``) governs
    /// and the soft limit is set just below that bound.
    public var protectionSoftLimit: UInt64 {
        switch self {
            case .aes128GcmSha256, .aes256GcmSha384:
                23_726_566
            case .chaCha20Poly1305Sha256:
                UInt64.max - 1
        }
    }
}
