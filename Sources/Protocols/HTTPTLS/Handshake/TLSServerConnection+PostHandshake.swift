//
//  TLSServerConnection+PostHandshake.swift
//  HTTPTLS
//
//  RFC 8446 §4.6 — post-handshake traffic: NewSessionTicket issuance over the vault seam,
//  KeyUpdate in both directions driven by Phase 3a's §5.5 counters, and the §7.5 exporter.
//  Post-handshake messages never enter the §4.4.1 transcript. Ticket issuance failures are
//  deliberately NOT funneled — a mis-configured vault costs a ticket, not the connection;
//  only record-layer failures (which genuinely poison the stream) reach the funnel.
//

public import Crypto

extension TLSServerConnection {
    /// §4.6.1: issues one NewSessionTicket over the configured vault.
    ///
    /// The nonce is the per-connection counter ("MUST be unique per ticket on this
    /// connection"); the PSK is
    /// derived per §4.6.1's `HKDF-Expand-Label(resumption_master_secret, "resumption",
    /// ticket_nonce, Hash.length)`.
    public mutating func issueSessionTicket() throws(TLSHandshakeError) {
        guard state == .connected, let ladder = schedule, let master = resumptionMaster,
            let suite = selectedSuite, let vault = configuration.ticketVault
        else {
            throw .sessionTicketsUnavailable  // caller error — connection stays usable
        }
        var nonce = TLSHandshakeBuilder()
        nonce.u32(UInt32(truncatingIfNeeded: ticketNonceCounter >> 32))
        nonce.u32(UInt32(truncatingIfNeeded: ticketNonceCounter))
        ticketNonceCounter += 1
        let ageAdd = configuration.entropy.ticketAgeAdd()
        let resumption = TLSResumptionState(
            preSharedKey: ladder.resumptionPreSharedKey(
                resumptionMasterSecret: master, ticketNonce: nonce.bytes
            ),
            hash: suite.hash,
            issuedAt: configuration.now(),
            lifetimeSeconds: configuration.ticketLifetimeSeconds,
            ageAdd: ageAdd,
            serverName: clientServerName,
            alpnProtocol: selectedAlpn
        )
        let ticket: [UInt8]
        do {
            ticket = try vault.sealTicket(resumption)
        }
        catch {
            throw .sessionTicketsUnavailable  // vault fault — not fatal, not funneled
        }
        do {
            try emit(
                handshake: TLSNewSessionTicketEncoder.newSessionTicket(
                    lifetimeSeconds: configuration.ticketLifetimeSeconds,
                    ageAdd: ageAdd,
                    nonce: nonce.bytes,
                    ticket: ticket
                )
            )
        }
        catch {
            throw fail(error)  // a record-layer refusal poisons the stream — funnel
        }
    }

    /// §4.6.3: the peer's KeyUpdate — ratchet our read; answer (then ratchet write) when requested.
    ///
    /// Bounds consecutive peer KeyUpdates without application data so an attacker cannot burn CPU
    /// with an infinite HKDF ratchet / reply flood.
    mutating func processKeyUpdate(
        _ message: TLSHandshakeCoalescer.Message
    ) throws(TLSHandshakeError) {
        try keyUpdates.receive(
            message,
            limit: configuration.maxConsecutivePeerKeyUpdates,
            record: &record
        )
    }

    /// Rekeys the write direction now, optionally demanding the peer rekey too (§4.6.3).
    public mutating func requestKeyUpdate(
        askPeerToUpdate: Bool = true
    ) throws(TLSHandshakeError) {
        guard state == .connected else {
            throw .connectionClosed
        }
        do {
            try sendKeyUpdate(requesting: askPeerToUpdate)
        }
        catch {
            throw fail(error)
        }
    }

    /// §5.5/§4.6.3: the automatic rekey driven by Phase 3a's counters — a write near its
    /// protection limit rekeys itself; a read near its limit asks the peer (once).
    mutating func maintainKeyUpdates() throws(TLSHandshakeError) {
        guard state == .connected else {
            return
        }
        try keyUpdates.maintain(record: &record)
    }

    /// Sends one KeyUpdate under the old write keys, then ratchets the write direction
    /// (§4.6.3's ordering).
    private mutating func sendKeyUpdate(requesting: Bool) throws(TLSHandshakeError) {
        try keyUpdates.send(requesting: requesting, record: &record)
    }

    /// §7.5 exporters over the exporter master secret — nil until the server Finished.
    public func exportKeyingMaterial(
        label: String, context: [UInt8], length: Int
    ) -> SymmetricKey? {
        guard let ladder = schedule, let exporterSecret else {
            return nil
        }
        return ladder.exportKeyingMaterial(
            exporterSecret: exporterSecret, label: label, context: context, length: length
        )
    }
}
