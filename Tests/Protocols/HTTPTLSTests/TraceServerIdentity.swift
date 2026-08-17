//
//  TraceServerIdentity.swift
//  HTTPTLSTests
//
//  The RFC 8448 fixture identity: returns the trace's certificate chain and its PUBLISHED
//  CertificateVerify signature verbatim. RSA-PSS signing is randomized, so no signer could
//  reproduce the trace's signature bytes — but the traces publish them, and the
//  ``TLSIdentityProvider`` seam returns (scheme, bytes), so byte-exact replay reduces to
//  handing the published signature back. The content assertion (the machine must ask for a
//  signature over exactly the §4.4.3 content the trace implies) is enforced downstream: a
//  wrong content would break the transcript and every subsequent secret and Finished.
//

internal import HTTPTLS

/// A fixture identity replaying an RFC 8448 trace's certificate + signature.
struct TraceServerIdentity: TLSIdentityProvider {
    /// The trace's DER chain (leaf only — the RFC 8448 server sends a single certificate).
    let certificateChainDER: [[UInt8]]
    /// The trace's published CertificateVerify scheme + signature.
    let signature: TLSSignature

    /// Returns the trace's signature, requiring its scheme to be among the candidates.
    func signature(
        over _: [UInt8], algorithms: [TLSSignatureScheme]
    ) async throws -> TLSSignature {
        guard algorithms.contains(signature.scheme) else {
            throw TLSHandshakeError.signingFailed
        }
        return signature
    }
}
