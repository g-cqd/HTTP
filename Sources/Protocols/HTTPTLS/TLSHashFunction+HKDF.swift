//
//  TLSHashFunction+HKDF.swift
//  HTTPTLS
//
//  RFC 8446 §7.1 — the three HKDF operations the key schedule is built from, dispatched onto
//  swift-crypto's `HKDF<SHA256>`/`HKDF<SHA384>` (never re-implemented):
//
//      HKDF-Extract(salt, IKM)
//      HKDF-Expand-Label(Secret, Label, Context, Length)   info = HkdfLabel
//      Derive-Secret(Secret, Label, Messages)              = Expand-Label(…, Transcript-Hash)
//
//  Secrets stay in `SymmetricKey` end to end. The ONE unsafe site in this file is the seam
//  swift-crypto's API shape forces: `HKDF.extract` takes its salt as `DataProtocol`, so a derived
//  salt (itself a secret `SymmetricKey`) must be momentarily materialized to feed it.
//

public import Crypto

internal import struct Foundation.Data

extension TLSHashFunction {
    /// `HKDF-Extract(salt, IKM)` (RFC 5869, as used by RFC 8446 §7.1's left column).
    public func extract(salt: SymmetricKey, inputKeyMaterial: SymmetricKey) -> SymmetricKey {
        // SAFETY: `HKDF.extract` accepts salt only as `DataProtocol`, so the secret salt is
        // copied into a `Data` scoped to this call and handed straight to swift-crypto; the
        // key material otherwise never leaves `SymmetricKey`.
        let saltData = unsafe salt.withUnsafeBytes { unsafe Data($0) }
        switch self {
            case .sha256:
                return SymmetricKey(
                    data: HKDF<SHA256>.extract(inputKeyMaterial: inputKeyMaterial, salt: saltData)
                )
            case .sha384:
                return SymmetricKey(
                    data: HKDF<SHA384>.extract(inputKeyMaterial: inputKeyMaterial, salt: saltData)
                )
        }
    }

    /// `HKDF-Expand-Label(Secret, Label, Context, Length)` (RFC 8446 §7.1) — `label` is the bare
    /// name; the `"tls13 "` prefix is applied here while encoding the `HkdfLabel` info.
    public func expandLabel(
        _ secret: SymmetricKey, label: String, context: [UInt8], length: Int
    ) -> SymmetricKey {
        let info = Self.hkdfLabelInfo(label: label, context: context, length: length)
        switch self {
            case .sha256:
                return HKDF<SHA256>
                    .expand(
                        pseudoRandomKey: secret, info: info, outputByteCount: length
                    )
            case .sha384:
                return HKDF<SHA384>
                    .expand(
                        pseudoRandomKey: secret, info: info, outputByteCount: length
                    )
        }
    }

    /// `Derive-Secret(Secret, Label, Messages)` (RFC 8446 §7.1) — the caller supplies
    /// `Transcript-Hash(Messages)`, since the transcript is accumulated incrementally.
    public func deriveSecret(
        _ secret: SymmetricKey, label: String, transcriptHash: [UInt8]
    ) -> SymmetricKey {
        expandLabel(secret, label: label, context: transcriptHash, length: digestByteCount)
    }

    /// `HMAC(key, message)` — §4.4.4's Finished verify_data primitive, surfaced here so the
    /// key schedule can compute and check verify_data without touching raw key bytes.
    public func authenticationCode(key: SymmetricKey, message: [UInt8]) -> [UInt8] {
        switch self {
            case .sha256:
                Array(HMAC<SHA256>.authenticationCode(for: message, using: key))
            case .sha384:
                Array(HMAC<SHA384>.authenticationCode(for: message, using: key))
        }
    }

    /// Encodes §7.1's `HkdfLabel`: `uint16 length` ∥ `opaque label<7..255>` (with the `"tls13 "`
    /// prefix) ∥ `opaque context<0..255>`.
    static func hkdfLabelInfo(label: String, context: [UInt8], length: Int) -> [UInt8] {
        let prefixed = "tls13 " + label
        var info: [UInt8] = []
        info.reserveCapacity(4 + prefixed.utf8.count + context.count)
        info.append(UInt8(truncatingIfNeeded: length >> 8))
        info.append(UInt8(truncatingIfNeeded: length))
        info.append(UInt8(truncatingIfNeeded: prefixed.utf8.count))
        info.append(contentsOf: prefixed.utf8)
        info.append(UInt8(truncatingIfNeeded: context.count))
        info.append(contentsOf: context)
        return info
    }
}
