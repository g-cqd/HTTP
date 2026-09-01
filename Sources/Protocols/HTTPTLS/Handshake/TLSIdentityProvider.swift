//
//  TLSIdentityProvider.swift
//  HTTPTLS
//
//  The server-identity seam (RFC 8446 §4.4.2/§4.4.3): the handshake machine consumes this
//  protocol and never touches private-key material — Phase 3c wires swift-certificates chains
//  and swift-crypto/SecKey signing behind it without touching the machine. Signing is async so
//  a hardware-backed or remote signer fits; scheme negotiation (§4.2.3) happens in the machine,
//  which passes the ALREADY-INTERSECTED candidate list (client's offer ∩ configuration, server
//  preference order) — the provider picks the first it can sign with.
//

/// The server's certificate + signing identity (RFC 8446 §4.4.2/§4.4.3) — Phase 3c's seam.
public protocol TLSIdentityProvider: Sendable {
    /// The certificate chain, leaf first, DER-encoded (§4.4.2's `CertificateEntry` order).
    var certificateChainDER: [[UInt8]] { get }

    /// Signs the §4.4.3 content under the first workable scheme from `algorithms` (already
    /// intersected with the client's offer, server preference order). Throwing is fatal to the
    /// handshake (`internal_error` — the peer learns nothing about the cause).
    func signature(
        over content: [UInt8], algorithms: [TLSSignatureScheme]
    ) async throws -> TLSSignature
}
