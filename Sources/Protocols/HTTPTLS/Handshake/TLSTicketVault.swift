//
//  TLSTicketVault.swift
//  HTTPTLS
//
//  The session-ticket seam (RFC 8446 §4.6.1/§4.2.11): sealing turns a ``TLSResumptionState``
//  into the opaque ticket a NewSessionTicket carries; opening redeems a ClientHello PSK
//  identity. Opening returns nil — never throws — for anything that is not a live ticket of
//  ours: §4.2.11 lets a server simply not resume, so an alien/expired/tampered ticket
//  degrades to a full handshake instead of leaking an error. The default implementation is
//  the stateless self-encrypted ``TLSStatelessTicketVault``; the protocol exists so tests can
//  inject known PSKs (the RFC 8448 §4 gate) and deployments can share state across hosts.
//

/// Seals and redeems session tickets (RFC 8446 §4.6.1).
public protocol TLSTicketVault: Sendable {
    /// Seals a resumption state into ticket octets. Throwing aborts only the ticket, never
    /// the connection.
    func sealTicket(_ state: TLSResumptionState) throws -> [UInt8]

    /// Redeems a ClientHello PSK identity: the live state, or nil for any ticket that is not
    /// ours, expired at `now`, or damaged (indistinguishably — no oracle).
    func openTicket(_ ticket: [UInt8], at now: UInt64) -> TLSResumptionState?
}
