//
//  TLSKeySchedule.swift
//  HTTPTLS
//
//  RFC 8446 §7.1 — the full key-derivation tree, as a strict three-stage ladder:
//
//      0/PSK ─HKDF-Extract→ Early Secret      ("ext binder"/"res binder", "c e traffic",
//            │                                 "e exp master")
//            ─"derived"→ salt
//      ECDHE ─HKDF-Extract→ Handshake Secret  ("c hs traffic", "s hs traffic")
//            ─"derived"→ salt
//      0     ─HKDF-Extract→ Master Secret     ("c ap traffic", "s ap traffic",
//                                              "exp master", "res master")
//
//  Every secret lives in `SymmetricKey`; transcript hashes are supplied by the caller (the
//  handshake machine drives ``TLSTranscriptHash`` and passes ``TLSTranscriptHash/currentHash``).
//  The "0" salts/IKMs are `Hash.length` zero octets — per RFC 2104's zero-padding of HMAC keys
//  this is exactly RFC 5869's absent salt, and RFC 8448 prints them the same way.
//

public import Crypto

/// The RFC 8446 §7.1 key schedule: early → handshake → master, one secret per derivation.
public struct TLSKeySchedule {
    /// The §7.1 ladder position (each Extract advances it; it never moves backwards).
    public enum Stage: Sendable, Equatable {
        /// Before any Extract — the schedule holds no secret yet.
        case initial
        /// The Early Secret is live (§7.1's first Extract, over the PSK or zeros).
        case early
        /// The Handshake Secret is live (second Extract, over the ECDHE shared secret).
        case handshake
        /// The Master Secret is live (third Extract, over zeros).
        case master
    }

    /// The suite's hash (fixes `Hash.length` for every derivation).
    public let hash: TLSHashFunction
    /// The current ladder position.
    public private(set) var stage: Stage = .initial
    /// The live left-column secret of §7.1's diagram.
    private var secret: SymmetricKey

    /// Creates an empty schedule for the suite's hash.
    public init(hash: TLSHashFunction) {
        self.hash = hash
        secret = hash.zeroKey
    }

    /// First Extract (§7.1): `Early Secret = HKDF-Extract(0, PSK or 0)`.
    public mutating func deriveEarlySecret(
        preSharedKey: SymmetricKey? = nil
    ) throws(TLSKeyScheduleError) {
        guard stage == .initial else {
            throw .wrongStage
        }
        secret = hash.extract(salt: hash.zeroKey, inputKeyMaterial: preSharedKey ?? hash.zeroKey)
        stage = .early
    }

    /// `binder_key = Derive-Secret(Early, "ext binder" | "res binder", "")` (§7.1, §4.2.11.2).
    public func binderKey(external: Bool) throws(TLSKeyScheduleError) -> SymmetricKey {
        try requireStage(.early)
        let label = external ? "ext binder" : "res binder"
        return hash.deriveSecret(secret, label: label, transcriptHash: hash.emptyTranscriptHash)
    }

    /// `client_early_traffic_secret = Derive-Secret(Early, "c e traffic", ClientHello)` (§7.1).
    public func clientEarlyTrafficSecret(
        transcriptHash: [UInt8]
    ) throws(TLSKeyScheduleError) -> SymmetricKey {
        try requireStage(.early)
        return hash.deriveSecret(secret, label: "c e traffic", transcriptHash: transcriptHash)
    }

    /// `early_exporter_master_secret = Derive-Secret(Early, "e exp master", ClientHello)` (§7.1).
    public func earlyExporterMasterSecret(
        transcriptHash: [UInt8]
    ) throws(TLSKeyScheduleError) -> SymmetricKey {
        try requireStage(.early)
        return hash.deriveSecret(secret, label: "e exp master", transcriptHash: transcriptHash)
    }

    /// Second Extract (§7.1): `Handshake Secret = HKDF-Extract(Derive-Secret(Early, "derived",
    /// ""), ECDHE)` — `sharedSecret` is the raw (EC)DHE output held as key material.
    public mutating func deriveHandshakeSecret(
        ecdhe sharedSecret: SymmetricKey
    ) throws(TLSKeyScheduleError) {
        guard stage == .early else {
            throw .wrongStage
        }
        secret = hash.extract(salt: derivedSalt(), inputKeyMaterial: sharedSecret)
        stage = .handshake
    }

    /// Second Extract over a swift-crypto key-agreement result (X25519/P-256 — §7.4.1/§7.4.2).
    public mutating func deriveHandshakeSecret(
        sharedSecret: SharedSecret
    ) throws(TLSKeyScheduleError) {
        try deriveHandshakeSecret(ecdhe: SymmetricKey(data: sharedSecret))
    }

    /// `client_handshake_traffic_secret = Derive-Secret(HS, "c hs traffic", CH..SH)` (§7.1).
    public func clientHandshakeTrafficSecret(
        transcriptHash: [UInt8]
    ) throws(TLSKeyScheduleError) -> SymmetricKey {
        try requireStage(.handshake)
        return hash.deriveSecret(secret, label: "c hs traffic", transcriptHash: transcriptHash)
    }

    /// `server_handshake_traffic_secret = Derive-Secret(HS, "s hs traffic", CH..SH)` (§7.1).
    public func serverHandshakeTrafficSecret(
        transcriptHash: [UInt8]
    ) throws(TLSKeyScheduleError) -> SymmetricKey {
        try requireStage(.handshake)
        return hash.deriveSecret(secret, label: "s hs traffic", transcriptHash: transcriptHash)
    }

    /// Third Extract (§7.1): `Master Secret = HKDF-Extract(Derive-Secret(HS, "derived", ""), 0)`.
    public mutating func deriveMasterSecret() throws(TLSKeyScheduleError) {
        guard stage == .handshake else {
            throw .wrongStage
        }
        secret = hash.extract(salt: derivedSalt(), inputKeyMaterial: hash.zeroKey)
        stage = .master
    }

    /// `client_application_traffic_secret_0 = Derive-Secret(MS, "c ap traffic", CH..server
    /// Finished)` (§7.1).
    public func clientApplicationTrafficSecret(
        transcriptHash: [UInt8]
    ) throws(TLSKeyScheduleError) -> SymmetricKey {
        try requireStage(.master)
        return hash.deriveSecret(secret, label: "c ap traffic", transcriptHash: transcriptHash)
    }

    /// `server_application_traffic_secret_0 = Derive-Secret(MS, "s ap traffic", CH..server
    /// Finished)` (§7.1).
    public func serverApplicationTrafficSecret(
        transcriptHash: [UInt8]
    ) throws(TLSKeyScheduleError) -> SymmetricKey {
        try requireStage(.master)
        return hash.deriveSecret(secret, label: "s ap traffic", transcriptHash: transcriptHash)
    }

    /// `exporter_master_secret = Derive-Secret(MS, "exp master", CH..server Finished)` (§7.1).
    public func exporterMasterSecret(
        transcriptHash: [UInt8]
    ) throws(TLSKeyScheduleError) -> SymmetricKey {
        try requireStage(.master)
        return hash.deriveSecret(secret, label: "exp master", transcriptHash: transcriptHash)
    }

    /// `resumption_master_secret = Derive-Secret(MS, "res master", CH..client Finished)` (§7.1).
    public func resumptionMasterSecret(
        transcriptHash: [UInt8]
    ) throws(TLSKeyScheduleError) -> SymmetricKey {
        try requireStage(.master)
        return hash.deriveSecret(secret, label: "res master", transcriptHash: transcriptHash)
    }

    /// `Derive-Secret(Secret, "derived", "")` — the salt feeding the next Extract (§7.1).
    private func derivedSalt() -> SymmetricKey {
        hash.deriveSecret(secret, label: "derived", transcriptHash: hash.emptyTranscriptHash)
    }

    /// Fails closed unless the ladder is at `expected`.
    private func requireStage(_ expected: Stage) throws(TLSKeyScheduleError) {
        guard stage == expected else {
            throw .wrongStage
        }
    }
}
