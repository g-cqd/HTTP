//
//  TLSResumptionState.swift
//  HTTPTLS
//
//  RFC 8446 §4.6.1/§4.2.11 — what a session ticket must carry for a later resumption: the
//  per-ticket PSK (already derived via `HKDF-Expand-Label(resumption_master_secret,
//  "resumption", ticket_nonce, Hash.length)`, §4.6.1), the hash that PSK is bound to
//  (§4.2.11: "the PSK MUST be associated with a hash... the cipher suite's"), the issue
//  clock data for the lifetime check, and the SNI/ALPN the original connection ran under so a
//  resumption cannot smuggle the PSK across server identities or protocols (§4.6.1: tickets
//  SHOULD only be resumed with compatible parameters — enforced here by skip-on-mismatch).
//

public import Crypto

/// The state a session ticket carries (RFC 8446 §4.6.1) — the vault's plaintext.
public struct TLSResumptionState: Sendable, Equatable {
    /// The per-ticket resumption PSK (§4.6.1's derivation, done at issue time).
    public var preSharedKey: SymmetricKey
    /// The hash the PSK is bound to (§4.2.11 — must match the resumed suite's hash).
    public var hash: TLSHashFunction
    /// When the ticket was issued, in the configuration clock's seconds.
    public var issuedAt: UInt64
    /// `ticket_lifetime` seconds (§4.6.1; ≤ 604800).
    public var lifetimeSeconds: UInt32
    /// `ticket_age_add` (§4.6.1) — carried for §4.2.11.1 age math; unused while 0-RTT is
    /// rejected (age freshness only guards 0-RTT anti-replay, §8.2).
    public var ageAdd: UInt32
    /// The SNI the issuing connection served, if any (resumption must match).
    public var serverName: String?
    /// The ALPN protocol the issuing connection negotiated, if any (resumption must match).
    public var alpnProtocol: String?

    /// Creates a resumption state.
    public init(
        preSharedKey: SymmetricKey,
        hash: TLSHashFunction,
        issuedAt: UInt64,
        lifetimeSeconds: UInt32,
        ageAdd: UInt32,
        serverName: String?,
        alpnProtocol: String?
    ) {
        self.preSharedKey = preSharedKey
        self.hash = hash
        self.issuedAt = issuedAt
        self.lifetimeSeconds = lifetimeSeconds
        self.ageAdd = ageAdd
        self.serverName = serverName
        self.alpnProtocol = alpnProtocol
    }

    /// Whether the ticket is still inside its §4.6.1 lifetime at `now`.
    public func isLive(at now: UInt64) -> Bool {
        now >= issuedAt && now - issuedAt < UInt64(lifetimeSeconds)
    }
}
