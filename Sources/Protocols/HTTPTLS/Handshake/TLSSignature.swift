//
//  TLSSignature.swift
//  HTTPTLS
//
//  RFC 8446 §4.4.3 — a produced handshake signature, as returned by the
//  ``TLSIdentityProvider`` seam: which §4.2.3 scheme it was made under, and the octets in
//  that scheme's wire encoding.
//

/// A produced handshake signature (RFC 8446 §4.4.3): the scheme it was made under + octets.
public struct TLSSignature: Sendable, Equatable {
    /// The scheme the signature was produced under — MUST be one of the offered candidates.
    public let scheme: TLSSignatureScheme
    /// The signature octets in the scheme's wire encoding (§4.2.3 — ECDSA is DER
    /// `Ecdsa-Sig-Value`; RSA-PSS is the raw PSS block; Ed25519 is the 64-octet signature).
    public let bytes: [UInt8]

    /// Creates a signature result.
    public init(scheme: TLSSignatureScheme, bytes: [UInt8]) {
        self.scheme = scheme
        self.bytes = bytes
    }
}
