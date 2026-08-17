//
//  TLSPreSharedKeyIdentity.swift
//  HTTPTLS
//
//  RFC 8446 §4.2.11 — one `PskIdentity`: the opaque ticket and the §4.2.11.1 obfuscated age.
//  The age is carried, not validated: age freshness matters only for 0-RTT anti-replay
//  (§8.2), and this server rejects 0-RTT outright.
//

/// One offered PSK identity (RFC 8446 §4.2.11): the opaque ticket and its obfuscated age.
struct TLSPreSharedKeyIdentity: Sendable, Equatable {
    /// The opaque identity — for resumption, a ticket this server's vault issued (§4.6.1).
    let identity: [UInt8]
    /// `obfuscated_ticket_age` (§4.2.11.1) — carried for completeness, unused while 0-RTT is
    /// rejected.
    let obfuscatedTicketAge: UInt32
}
