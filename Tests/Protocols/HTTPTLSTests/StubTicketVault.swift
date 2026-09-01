//
//  StubTicketVault.swift
//  HTTPTLSTests
//
//  A ``TLSTicketVault`` that redeems exactly one known identity — the RFC 8448 §4 gate's
//  seam: the trace's ClientHello offers the ticket the trace's own server issued (whose
//  encryption key RFC 8448 does not publish), so the test injects the trace's PSK for that
//  exact identity blob and the machine's §4.2.11.2 binder verification must then accept it.
//

internal import HTTPTLS

/// A vault redeeming one fixed identity to one fixed resumption state.
struct StubTicketVault: TLSTicketVault {
    /// The one redeemable identity blob.
    let identity: [UInt8]
    /// The state it redeems to.
    let state: TLSResumptionState

    /// Sealing is unsupported — this stub only redeems.
    func sealTicket(_: TLSResumptionState) throws -> [UInt8] {
        throw TLSHandshakeError.sessionTicketsUnavailable
    }

    /// Redeems the fixed identity when live; anything else is nil (the no-oracle contract).
    func openTicket(_ ticket: [UInt8], at now: UInt64) -> TLSResumptionState? {
        guard ticket == identity, state.isLive(at: now) else {
            return nil
        }
        return state
    }
}
