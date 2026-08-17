//
//  TLSServerConnection+Resumption.swift
//  HTTPTLS
//
//  RFC 8446 §4.2.9/§4.2.11 — PSK resumption, receive side: identity redemption through the
//  ``TLSTicketVault`` seam, the §4.2.11 compatibility gates (hash, SNI, ALPN), and §4.2.11.2
//  binder verification over the TRUNCATED transcript. Failure grades matter: an identity that
//  does not redeem is silently skipped (full handshake — no oracle), but a redeemed identity
//  whose binder is wrong is FATAL (`decrypt_error`) — the binder is the proof of possession.
//  0-RTT is rejected deliberately even when the PSK is accepted (the Security.md posture):
//  early_data is parsed, never acknowledged, and the §4.2.10 skip window disposes of the
//  client's early records.
//

internal import Crypto

extension TLSServerConnection {
    /// The outcome of PSK selection: which identity and the resumption state behind it.
    struct SelectedPreSharedKey {
        /// The §4.2.11 `selected_identity` index for the ServerHello.
        let index: Int
        /// The vault-redeemed state (carries the PSK).
        let resumption: TLSResumptionState
    }

    /// §4.2.11: resolves the client's PSK offer to a redeemable identity, or nil for the
    /// full-handshake fallback.
    ///
    /// Fatal only for contract violations (§4.2.9's missing modes).
    func selectPreSharedKey(
        _ hello: TLSClientHello, suite: TLSCipherSuite
    ) throws(TLSHandshakeError) -> SelectedPreSharedKey? {
        guard let offer = hello.preSharedKey else {
            return nil
        }
        guard let modes = hello.pskKeyExchangeModes else {
            // §4.2.9: "If clients offer pre_shared_key without a psk_key_exchange_modes
            // extension, servers MUST abort the handshake."
            throw .missingExtension(.pskKeyExchangeModes)
        }
        guard offer.binders.count == offer.identities.count else {
            throw .invalidBinder  // §4.2.11.2: a missing binder cannot validate
        }
        guard modes.contains(TLSClientHello.pskDheKeMode),  // psk_dhe_ke only — never psk_ke
            let vault = configuration.ticketVault
        else {
            return nil
        }
        let now = configuration.now()
        for (index, identity) in offer.identities.enumerated() {
            guard let resumption = vault.openTicket(identity.identity, at: now),
                resumption.hash == suite.hash,  // §4.2.11: PSK↔hash binding
                resumption.serverName == hello.serverName,  // §4.6.1 compatibility
                resumption.alpnProtocol == selectedAlpn
            else {
                continue  // not ours / not live / incompatible — full handshake, no oracle
            }
            return SelectedPreSharedKey(index: index, resumption: resumption)
        }
        return nil
    }

    /// §4.2.11.2: verifies the selected identity's binder over
    /// `Transcript-Hash(Truncate(ClientHello))` — including the ClientHello1/HRR prefix when
    /// a retry happened (the transcript already holds it).
    ///
    /// The schedule must hold the PSK-fed Early Secret. "If ... it does not validate, the
    /// server MUST abort the handshake" — `decrypt_error`.
    func verifyBinder(
        offer: TLSPreSharedKeyOffer,
        selected: SelectedPreSharedKey,
        schedule: TLSKeySchedule,
        rawMessage: [UInt8],
        priorTranscript: TLSTranscriptHash?
    ) throws(TLSHandshakeError) {
        let binderKey: SymmetricKey
        do {
            binderKey = try schedule.binderKey(external: false)  // resumption PSKs (§7.1)
        }
        catch {
            throw .internalError("binder key stage")
        }
        var truncated = priorTranscript ?? TLSTranscriptHash(schedule.hash)
        truncated.append([UInt8](rawMessage[..<offer.truncatedMessageLength]))
        let expected = offer.binders[selected.index]
        guard
            schedule.hash.isValidAuthenticationCode(
                expected[...],
                key: schedule.finishedKey(for: binderKey),
                message: truncated.currentHash
            )
        else {
            throw .invalidBinder  // §4.2.11.2 — decrypt_error
        }
    }
}
