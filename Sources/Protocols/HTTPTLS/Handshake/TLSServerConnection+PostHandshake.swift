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

    /// §4.6.3: the peer's KeyUpdate — ratchet our read; answer (then ratchet write) when
    /// `update_requested`.
    mutating func processKeyUpdate(
        _ message: TLSHandshakeCoalescer.Message
    ) throws(TLSHandshakeError) {
        let update = try TLSKeyUpdateMessage.parse(message)
        do {
            try record.ratchetReadKeys()  // the peer already switched (§7.2)
        }
        catch {
            throw .record(error)
        }
        requestedPeerKeyUpdate = false  // whatever we asked for has now happened
        guard update == .updateRequested else {
            return
        }
        // §4.6.3: answer "with its own KeyUpdate with request_update set to
        // update_not_requested prior to sending its next Application Data record" — the
        // answer rides the OLD write keys, then the write direction ratchets.
        try emit(handshake: TLSKeyUpdateMessage.updateNotRequested.encoded())
        do {
            try record.ratchetWriteKeys()
        }
        catch {
            throw .record(error)
        }
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
        let writeNeed = record.writeNeedsKeyUpdate
        let readNeed = record.readNeedsKeyUpdate && !requestedPeerKeyUpdate
        guard writeNeed || readNeed else {
            return
        }
        try sendKeyUpdate(requesting: readNeed)
    }

    /// Sends one KeyUpdate under the old write keys, then ratchets the write direction
    /// (§4.6.3's ordering).
    private mutating func sendKeyUpdate(requesting: Bool) throws(TLSHandshakeError) {
        let message: TLSKeyUpdateMessage = requesting ? .updateRequested : .updateNotRequested
        try emit(handshake: message.encoded())
        do {
            try record.ratchetWriteKeys()
        }
        catch {
            throw .record(error)
        }
        if requesting {
            requestedPeerKeyUpdate = true
        }
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
