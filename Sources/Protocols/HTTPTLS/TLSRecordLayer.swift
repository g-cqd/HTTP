//
//  TLSRecordLayer.swift
//  HTTPTLS
//
//  RFC 8446 §5 — the sans-I/O record layer of a TLS 1.3 SERVER connection: feed it wire octets
//  (`receive`), collect typed events; queue content (`send…`), drain wire octets
//  (`outboundBytes`). No sockets, no concurrency — the transport driver owns one instance per
//  connection and pumps it, exactly like `HTTP2Connection`. Phase 3b's handshake machine sits on
//  top: it consumes ``TLSRecordEvent``s and drives the key ladder here via ``installReadKeys``/
//  ``installWriteKeys`` (§7.1's epochs) and the §7.2 ``ratchetReadKeys``/``ratchetWriteKeys``.
//
//  This file owns the state and the key ladder; deframing lives in +Receive, framing in +Send.
//

public import Crypto

/// The sans-I/O TLS 1.3 record layer (RFC 8446 §5): octets in, events out, per-direction keys.
public struct TLSRecordLayer {
    /// The negotiated suite — fixed by the first key installation; every later installation
    /// must agree (§7: one suite per connection).
    public private(set) var suite: TLSCipherSuite?
    /// The read (client → server) epoch.
    public private(set) var readEpoch: TLSKeyEpoch = .plaintext
    /// The write (server → client) epoch.
    public private(set) var writeEpoch: TLSKeyEpoch = .plaintext
    /// The read direction's protection state (nil at the plaintext epoch).
    var readProtector: TLSRecordProtector?
    /// The write direction's protection state (nil at the plaintext epoch).
    var writeProtector: TLSRecordProtector?
    /// A partial inbound record awaiting more octets (capacity fixed at one max record).
    var holdback: [UInt8]
    /// Queued outbound wire octets, drained by ``outboundBytes()``.
    var outbound: [UInt8] = []
    /// Whether any handshake record has arrived — opens the §5/D.4 CCS tolerance window
    /// ("at any time after the first ClientHello message has been received").
    var sawHandshakeRecord = false
    /// The §5.4 padding policy for sealed records: each inner plaintext is rounded up to a
    /// multiple of this many octets (0 or 1 = no padding).
    public var paddingGranularity = 0
    /// The outbound fragmentation cap — §5.1's 2^14 by default, lowered when the peer
    /// negotiates a smaller RFC 8449 `record_size_limit` (the limit covers the whole
    /// `TLSInnerPlaintext`, so the driver sets `limit - 1` here).
    public var maxOutboundFragmentLength = TLSRecordLimits.maxPlaintextLength
    /// RFC 8446 §4.2.10's early-data skip window: while non-nil (the handshake machine opens
    /// it after REJECTING offered early data, §7.1 handshake read epoch only), records that
    /// fail deprotection are silently discarded and their ciphertext octets charged here;
    /// exhausting the budget — the "configured max_early_data_size" — is fatal.
    public var earlyDataSkipBudget: Int?

    /// Creates a record layer at the unprotected epoch in both directions.
    public init() {
        holdback = []
        holdback.reserveCapacity(TLSRecordLimits.headerLength + TLSRecordLimits.maxCiphertextLength)
    }

    /// Drains every queued outbound octet (records already framed/sealed by the `send…` calls).
    public mutating func outboundBytes() -> [UInt8] {
        let bytes = outbound
        outbound = []
        return bytes
    }

    // MARK: The key ladder (§7.1 epochs, driven by Phase 3b)

    /// Installs the next read epoch's traffic keys (plaintext → handshake → application).
    ///
    /// Records still in flight under the old keys fail §5.2 deprotection — retired keys never
    /// open anything.
    public mutating func installReadKeys(
        suite: TLSCipherSuite, trafficSecret: SymmetricKey
    ) throws(TLSRecordError) {
        let epoch = try climb(from: readEpoch, suite: suite)
        readProtector = TLSRecordProtector(suite: suite, trafficSecret: trafficSecret)
        readEpoch = epoch
    }

    /// Installs the next write epoch's traffic keys (plaintext → handshake → application).
    public mutating func installWriteKeys(
        suite: TLSCipherSuite, trafficSecret: SymmetricKey
    ) throws(TLSRecordError) {
        let epoch = try climb(from: writeEpoch, suite: suite)
        writeProtector = TLSRecordProtector(suite: suite, trafficSecret: trafficSecret)
        writeEpoch = epoch
    }

    /// §7.2: ratchets the read direction to `traffic_secret_N+1` (after the peer's KeyUpdate).
    public mutating func ratchetReadKeys() throws(TLSRecordError) {
        guard readEpoch == .application, readProtector != nil else {
            throw .invalidKeyInstallation  // §7.2 ratchets exist only for application keys
        }
        readProtector?.ratchet()
    }

    /// §7.2: ratchets the write direction to `traffic_secret_N+1` (alongside our KeyUpdate).
    public mutating func ratchetWriteKeys() throws(TLSRecordError) {
        guard writeEpoch == .application, writeProtector != nil else {
            throw .invalidKeyInstallation
        }
        writeProtector?.ratchet()
    }

    /// Validates one rung of the ladder: strictly forward, one suite per connection.
    private mutating func climb(
        from epoch: TLSKeyEpoch, suite: TLSCipherSuite
    ) throws(TLSRecordError) -> TLSKeyEpoch {
        guard let next = epoch.next else {
            throw .invalidKeyInstallation
        }
        if let negotiated = self.suite, negotiated != suite {
            throw .invalidKeyInstallation
        }
        self.suite = suite
        return next
    }

    // MARK: §5.5 record-limit visibility (Phase 3b drives KeyUpdate from these)

    /// The read direction's next sequence number (records opened under the current keys).
    public var readSequenceNumber: UInt64 {
        readProtector?.sequenceNumber ?? 0
    }

    /// The write direction's next sequence number (records sealed under the current keys).
    public var writeSequenceNumber: UInt64 {
        writeProtector?.sequenceNumber ?? 0
    }

    /// Whether the peer must be asked to rekey soon (§5.5 margin on the read direction).
    public var readNeedsKeyUpdate: Bool {
        readProtector?.needsKeyUpdate ?? false
    }

    /// Whether this side must send KeyUpdate soon (§5.5 margin on the write direction).
    public var writeNeedsKeyUpdate: Bool {
        writeProtector?.needsKeyUpdate ?? false
    }
}
