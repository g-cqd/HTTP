//
//  TLSVerifyPeerHookValidator.swift
//  HTTPTLS
//
//  The adapter that carries the portable backbone's trust hook into the engine unchanged:
//  `TransportTLS.verifyPeer` is `@Sendable ([[UInt8]]) -> Bool` over the leaf-first DER
//  chain, and Phase 3d passes exactly that closure here. A `false` maps to §6.2
//  `bad_certificate` — the hook's boolean carries no failure class, and `bad_certificate`
//  is §6.2's "otherwise unusable" catch-all (the class-specific alerts are
//  ``TLSX509ChainValidator``'s, which knows WHY it rejected).
//

/// Wraps a boolean `verifyPeer`-style hook as a ``TLSClientChainValidator``.
public struct TLSVerifyPeerHookValidator: TLSClientChainValidator {
    /// The hook: leaf-first DER chain in, accept/reject out.
    private let hook: @Sendable ([[UInt8]]) -> Bool

    /// Wraps `hook` (the exact `TransportTLS.verifyPeer` shape).
    public init(_ hook: @escaping @Sendable ([[UInt8]]) -> Bool) {
        self.hook = hook
    }

    /// Applies the hook; `false` is §6.2 `bad_certificate`.
    public func validate(chainDER: [[UInt8]]) async -> TLSChainVerdict {
        hook(chainDER) ? .accepted : .rejected(.badCertificate("verifyPeer hook rejected"))
    }
}
