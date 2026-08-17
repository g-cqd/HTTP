//
//  TLSRecordLayer+Send.swift
//  HTTPTLS
//
//  RFC 8446 §5.1 — outbound framing. Content is fragmented at the 2^14 cap, then either framed
//  as an unprotected record (plaintext epoch: ServerHello and friends, with the frozen 0x0303
//  legacy version) or sealed under the current write keys (§5.2, via the protector). The §5.4
//  padding policy (`paddingGranularity`) applies to every sealed record; the D.4 middlebox
//  `change_cipher_spec` is written verbatim — CCS is never protected.
//

extension TLSRecordLayer {
    /// Queues handshake content (§4 messages, back to back), fragmented per §5.1 and sealed
    /// when the write epoch has keys.
    public mutating func send(handshake bytes: [UInt8]) throws(TLSRecordError) {
        try enqueue(type: .handshake, content: bytes)
    }

    /// Queues application data — application write epoch only.
    ///
    /// Zero-length is legal (§5.1) and produces one padded-only record.
    public mutating func send(applicationData bytes: [UInt8]) throws(TLSRecordError) {
        guard writeEpoch == .application else {
            throw .invalidKeyInstallation  // §7.1: app data flows only under app keys
        }
        try enqueue(type: .applicationData, content: bytes)
    }

    /// Queues one alert (§6: alone in its record), protected per the current write state.
    public mutating func send(alert: TLSAlert) throws(TLSRecordError) {
        try enqueue(type: .alert, content: [alert.level, alert.description.rawValue])
    }

    /// Queues the Appendix D.4 middlebox-compatibility `change_cipher_spec` — one unprotected
    /// 0x01 octet, sent by a server right after ServerHello (so before any write keys).
    public mutating func sendChangeCipherSpec() throws(TLSRecordError) {
        guard writeEpoch == .plaintext else {
            throw .invalidKeyInstallation  // CCS is never protected (§5)
        }
        outbound.append(TLSContentType.changeCipherSpec.rawValue)
        outbound.append(TLSRecordLimits.legacyVersionMajor)
        outbound.append(TLSRecordLimits.legacyVersionMinor)
        outbound.append(0)
        outbound.append(1)
        outbound.append(1)
    }

    /// Fragments `content` at the §5.1 cap and frames/seals each fragment.
    private mutating func enqueue(
        type: TLSContentType, content: [UInt8]
    ) throws(TLSRecordError) {
        var start = content.startIndex
        repeat {
            let end = min(start + TLSRecordLimits.maxPlaintextLength, content.endIndex)
            try enqueueRecord(type: type, fragment: content[start ..< end])
            start = end
        } while start < content.endIndex
    }

    /// Frames one fragment: an unprotected §5.1 record at the plaintext epoch, a §5.2 sealed
    /// record (with the §5.4 padding policy) once write keys exist.
    private mutating func enqueueRecord(
        type: TLSContentType, fragment: ArraySlice<UInt8>
    ) throws(TLSRecordError) {
        guard var protector = writeProtector else {
            outbound.append(type.rawValue)
            outbound.append(TLSRecordLimits.legacyVersionMajor)
            outbound.append(TLSRecordLimits.legacyVersionMinor)  // §5.1: senders write 0x0303
            outbound.append(UInt8(truncatingIfNeeded: fragment.count >> 8))
            outbound.append(UInt8(truncatingIfNeeded: fragment.count))
            outbound.append(contentsOf: fragment)
            return
        }
        try protector.seal(
            type: type,
            fragment: fragment,
            paddedLength: paddedLength(for: fragment.count),
            into: &outbound
        )
        writeProtector = protector
    }

    /// The §5.4 padding target for one fragment under ``TLSRecordLayer/paddingGranularity``.
    private func paddedLength(for fragmentCount: Int) -> Int {
        guard paddingGranularity > 1 else {
            return 0
        }
        let inner = fragmentCount + 1  // content ∥ inner type octet
        let rounded = (inner + paddingGranularity - 1) / paddingGranularity * paddingGranularity
        return min(rounded, TLSRecordLimits.maxInnerPlaintextLength)
    }
}
