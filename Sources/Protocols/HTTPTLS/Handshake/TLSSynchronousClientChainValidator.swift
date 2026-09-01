//
//  TLSSynchronousClientChainValidator.swift
//  HTTPTLS
//
//  The synchronous refinement of the client-chain trust seam (Phase 3d), the validator twin
//  of ``TLSSynchronousIdentityProvider``: ``TLSClientChainValidator`` is async because
//  swift-certificates' `Verifier` is, but a `verifyPeer`-shaped hook
//  (``TLSVerifyPeerHookValidator``) judges without suspension — and the portable backbone's
//  engine adapter, which drives the handshake under a `Mutex`, needs that fact to be
//  spellable. The synchronous drive (``TLSServerConnection/receiveSynchronously(_:)``)
//  consults this refinement and fails closed (`internal_error`) on validators that only
//  offer the async surface.
//

/// A ``TLSClientChainValidator`` whose verdict arrives without suspension (RFC 5280 §6).
public protocol TLSSynchronousClientChainValidator: TLSClientChainValidator {
    /// Judges `chainDER` — the ``TLSClientChainValidator/validate(chainDER:)`` contract,
    /// without suspension.
    func validateSynchronously(chainDER: [[UInt8]]) -> TLSChainVerdict
}
