//
//  TLSKeyUpdateState.swift
//  HTTPTLS
//
//  RFC 8446 §4.6.3 / §5.5 — the post-handshake KeyUpdate machinery shared by both connection
//  roles: answering a peer KeyUpdate (bounded, so an attacker cannot burn CPU with an endless
//  HKDF ratchet / reply flood), sending one under the old write keys then ratcheting, and the
//  automatic rekey driven by the record layer's protection-limit counters.
//

/// Per-connection KeyUpdate bookkeeping (RFC 8446 §4.6.3).
struct TLSKeyUpdateState: Sendable {
    /// Peer KeyUpdates received without intervening application data.
    var consecutivePeerUpdates = 0
    /// Whether we asked the peer to update and it has not yet done so.
    var requestedPeerUpdate = false

    /// §4.6.3: the peer's KeyUpdate — ratchet our read; answer (then ratchet write) when requested.
    mutating func receive(
        _ message: TLSHandshakeCoalescer.Message,
        limit: Int,
        record: inout TLSRecordLayer
    ) throws(TLSHandshakeError) {
        let update = try TLSKeyUpdateMessage.parse(message)
        consecutivePeerUpdates += 1
        guard consecutivePeerUpdates <= limit else {
            throw .excessiveKeyUpdates
        }
        try Self.recordStep { () throws(TLSRecordError) in
            try record.ratchetReadKeys()  // the peer already switched (§7.2)
        }
        requestedPeerUpdate = false  // whatever we asked for has now happened
        guard update == .updateRequested else {
            return
        }
        // §4.6.3: answer with update_not_requested before the next application data, under the
        // OLD write keys, then ratchet the write direction.
        try send(requesting: false, record: &record)
    }

    /// §5.5: a write near its protection limit rekeys itself; a read near its limit asks the
    /// peer (once).
    mutating func maintain(record: inout TLSRecordLayer) throws(TLSHandshakeError) {
        let writeNeed = record.writeNeedsKeyUpdate
        let readNeed = record.readNeedsKeyUpdate && !requestedPeerUpdate
        guard writeNeed || readNeed else {
            return
        }
        try send(requesting: readNeed, record: &record)
    }

    /// Sends one KeyUpdate under the old write keys, then ratchets the write direction.
    mutating func send(requesting: Bool, record: inout TLSRecordLayer) throws(TLSHandshakeError) {
        let message: TLSKeyUpdateMessage = requesting ? .updateRequested : .updateNotRequested
        try Self.recordStep { () throws(TLSRecordError) in
            try record.send(handshake: message.encoded())
            try record.ratchetWriteKeys()
        }
        if requesting {
            requestedPeerUpdate = true
        }
    }

    private static func recordStep(
        _ body: () throws(TLSRecordError) -> Void
    ) throws(TLSHandshakeError) {
        do {
            try body()
        }
        catch {
            throw .record(error)
        }
    }
}
