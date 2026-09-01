//
//  TLSNewSessionTicket.swift
//  HTTPTLS
//
//  RFC 8446 §4.6.1 — the NewSessionTicket encoder. The ticket itself is the vault's sealed
//  blob (stateless, self-encrypted — ``TLSStatelessTicketVault``); this encoder frames it with
//  the lifetime (≤ 604800 seconds, §4.6.1), the anti-correlation `ticket_age_add`, and the
//  per-ticket `ticket_nonce` that makes each ticket's PSK unique (§4.6.1: "MUST be unique per
//  ticket on this connection"). No `early_data` extension is ever attached — this server never
//  invites 0-RTT (Security.md posture; §4.2.10 is the decline path).
//

/// The NewSessionTicket encoder (RFC 8446 §4.6.1).
enum TLSNewSessionTicketEncoder {
    /// The §4.6.1 ceiling on `ticket_lifetime`: seven days.
    static let maximumLifetimeSeconds: UInt32 = 604_800

    /// Encodes one NewSessionTicket.
    static func newSessionTicket(
        lifetimeSeconds: UInt32,
        ageAdd: UInt32,
        nonce: [UInt8],
        ticket: [UInt8]
    ) -> [UInt8] {
        TLSHandshakeBuilder.message(.newSessionTicket) { message in
            message.u32(min(lifetimeSeconds, maximumLifetimeSeconds))  // §4.6.1 cap
            message.u32(ageAdd)
            message.vector8 { $0.raw(nonce) }
            message.vector16 { $0.raw(ticket) }
            message.vector16 { _ in
                // extensions: none — no early_data invitation, ever
            }
        }
    }
}
