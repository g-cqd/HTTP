//
//  TLSClientChainValidator.swift
//  HTTPTLS
//
//  The client-chain trust seam (Phase 3c) — the engine's form of the portable backbone's
//  `verifyPeer` hook: the presented DER chain in (leaf first, the backbone-agnostic
//  currency both backbones already share), a verdict out. Async because the reference
//  implementation (``TLSX509ChainValidator``) rides swift-certificates' `Verifier`, whose
//  `validate` is `async` — the one 3c surface that did not fit a synchronous hook. The
//  CONTRACT stays the existing seam's: a deployment's `@Sendable ([[UInt8]]) -> Bool` hook
//  passes straight through via ``TLSVerifyPeerHookValidator`` (a sync closure fits an async
//  seam for free; the reverse would have required blocking a cooperative thread).
//

/// Validates a presented client-certificate chain during the handshake (RFC 5280 §6,
/// RFC 8446 §4.4.2).
public protocol TLSClientChainValidator: Sendable {
    /// Judges `chainDER` (leaf first, one DER certificate per element; never empty — chain
    /// ABSENCE is the ``TLSClientAuthenticationMode``'s decision, not the validator's).
    func validate(chainDER: [[UInt8]]) async -> TLSChainVerdict
}
