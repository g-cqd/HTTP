//
//  TLSKeySchedule+Derived.swift
//  HTTPTLS
//
//  The stage-independent derivations hanging off the §7.1 tree's leaves: Finished keys
//  (§4.4.4), the §7.2 KeyUpdate ratchet, the §4.6.1 resumption PSK, and the §7.5 exporter.
//  All are pure functions of a leaf secret, so they take the secret explicitly rather than
//  reading the ladder — the handshake machine holds the leaves it is entitled to.
//

public import Crypto

extension TLSKeySchedule {
    /// `finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)` (§4.4.4).
    public func finishedKey(for baseKey: SymmetricKey) -> SymmetricKey {
        hash.expandLabel(baseKey, label: "finished", context: [], length: hash.digestByteCount)
    }

    /// `verify_data = HMAC(finished_key, Transcript-Hash(...))` (§4.4.4) for the given
    /// handshake traffic secret.
    public func finishedVerifyData(
        trafficSecret: SymmetricKey, transcriptHash: [UInt8]
    ) -> [UInt8] {
        hash.authenticationCode(key: finishedKey(for: trafficSecret), message: transcriptHash)
    }

    /// §7.2's ratchet: `traffic_secret_N+1 = HKDF-Expand-Label(traffic_secret_N, "traffic upd",
    /// "", Hash.length)` — the KeyUpdate step the record layer applies per direction.
    public static func nextTrafficSecret(
        after secret: SymmetricKey, hash: TLSHashFunction
    ) -> SymmetricKey {
        hash.expandLabel(secret, label: "traffic upd", context: [], length: hash.digestByteCount)
    }

    /// §4.6.1's per-ticket PSK: `HKDF-Expand-Label(resumption_master_secret, "resumption",
    /// ticket_nonce, Hash.length)`.
    public func resumptionPreSharedKey(
        resumptionMasterSecret: SymmetricKey, ticketNonce: [UInt8]
    ) -> SymmetricKey {
        hash.expandLabel(
            resumptionMasterSecret,
            label: "resumption",
            context: ticketNonce,
            length: hash.digestByteCount
        )
    }

    /// §7.5 exporters: `HKDF-Expand-Label(Derive-Secret(Secret, label, ""), "exporter",
    /// Hash(context), key_length)` over the (early) exporter master secret.
    public func exportKeyingMaterial(
        exporterSecret: SymmetricKey, label: String, context: [UInt8], length: Int
    ) -> SymmetricKey {
        let derived = hash.deriveSecret(
            exporterSecret, label: label, transcriptHash: hash.emptyTranscriptHash
        )
        let contextHash: [UInt8] =
            switch hash {
                case .sha256:
                    Array(SHA256.hash(data: context))
                case .sha384:
                    Array(SHA384.hash(data: context))
            }
        return hash.expandLabel(derived, label: "exporter", context: contextHash, length: length)
    }
}
