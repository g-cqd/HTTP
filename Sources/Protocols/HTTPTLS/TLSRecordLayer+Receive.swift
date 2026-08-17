//
//  TLSRecordLayer+Receive.swift
//  HTTPTLS
//
//  RFC 8446 §5.1 — inbound deframing. Records are parsed straight out of the caller's buffer;
//  only a trailing PARTIAL record is copied into the fixed-capacity holdback (≤ one max record,
//  regardless of feed size), where the next feed completes it. Per §5.1 the legacy version
//  octets are ignored entirely; lengths are capped before payload bytes are even awaited, so a
//  length lie can never grow a buffer. Epoch dispatch — which record types may arrive
//  unprotected, the §5/D.4 change_cipher_spec tolerance window, and §5.4 inner types — is here
//  too, one funnel for every record regardless of which buffer it was assembled in.
//

extension TLSRecordLayer {
    /// Feeds inbound wire octets and returns the events of every record they complete.
    ///
    /// Any failure is fatal to the connection: the caller sends the error's
    /// ``TLSRecordError/alertDescription`` and discards the layer (fail closed).
    public mutating func receive(
        _ bytes: [UInt8]
    ) throws(TLSRecordError) -> [TLSRecordEvent] {
        var events: [TLSRecordEvent] = []
        var cursor = bytes.startIndex
        while true {
            if holdback.isEmpty {
                let remaining = bytes.endIndex - cursor
                guard remaining >= TLSRecordLimits.headerLength else {
                    stash(bytes, from: &cursor)
                    return events
                }
                let bodyLength = try validateHeader(bytes[cursor...])
                guard remaining >= TLSRecordLimits.headerLength + bodyLength else {
                    stash(bytes, from: &cursor)
                    return events
                }
                let bodyStart = cursor + TLSRecordLimits.headerLength
                try processRecord(
                    header: bytes[cursor ..< bodyStart],
                    body: bytes[bodyStart ..< bodyStart + bodyLength],
                    into: &events
                )
                cursor = bodyStart + bodyLength
            }
            else {
                topUpHoldback(from: bytes, cursor: &cursor, to: TLSRecordLimits.headerLength)
                guard holdback.count >= TLSRecordLimits.headerLength else {
                    return events
                }
                let bodyLength = try validateHeader(holdback[...])
                let recordLength = TLSRecordLimits.headerLength + bodyLength
                topUpHoldback(from: bytes, cursor: &cursor, to: recordLength)
                guard holdback.count == recordLength else {
                    return events
                }
                try processRecord(
                    header: holdback[..<TLSRecordLimits.headerLength],
                    body: holdback[TLSRecordLimits.headerLength...],
                    into: &events
                )
                holdback.removeAll(keepingCapacity: true)
            }
            if cursor == bytes.endIndex, holdback.isEmpty {
                return events
            }
        }
    }

    /// Copies the unconsumed tail (always < one record) into the holdback.
    private mutating func stash(_ bytes: [UInt8], from cursor: inout Int) {
        holdback.append(contentsOf: bytes[cursor...])
        cursor = bytes.endIndex
    }

    /// Moves octets into the holdback until it holds `target` octets or input runs dry.
    private mutating func topUpHoldback(
        from bytes: [UInt8], cursor: inout Int, to target: Int
    ) {
        let take = min(target - holdback.count, bytes.endIndex - cursor)
        guard take > 0 else {
            return
        }
        holdback.append(contentsOf: bytes[cursor ..< cursor + take])
        cursor += take
    }

    /// Checks the §5.1 outer content type and length cap, returning the body length.
    ///
    /// The two legacy version octets are ignored for all purposes (§5.1).
    private func validateHeader(_ header: ArraySlice<UInt8>) throws(TLSRecordError) -> Int {
        let base = header.startIndex
        guard let type = TLSContentType(rawValue: header[base]) else {
            throw .unknownContentType(header[base])  // §5: unexpected record type
        }
        let bodyLength = Int(header[base + 3]) << 8 | Int(header[base + 4])
        let cap =
            type == .applicationData
            ? TLSRecordLimits.maxCiphertextLength  // §5.2: 2^14 + 256
            : TLSRecordLimits.maxPlaintextLength  // §5.1: 2^14
        guard bodyLength <= cap else {
            throw .recordOverflow
        }
        return bodyLength
    }

    /// The single per-record funnel: epoch dispatch, deprotection, and event surfacing.
    private mutating func processRecord(
        header: ArraySlice<UInt8>, body: ArraySlice<UInt8>, into events: inout [TLSRecordEvent]
    ) throws(TLSRecordError) {
        // The outer type octet was validated by `validateHeader`.
        guard let outerType = TLSContentType(rawValue: header[header.startIndex]) else {
            throw .unknownContentType(header[header.startIndex])
        }
        switch outerType {
            case .changeCipherSpec:
                try tolerateChangeCipherSpec(body: body)  // §5 / D.4
            case .applicationData where readEpoch > .plaintext:
                try openProtectedRecord(header: header, body: body, into: &events)
            case .handshake, .alert:
                guard readEpoch == .plaintext else {
                    // §5.2/§6: once keys are installed, nothing legitimate arrives unprotected
                    // (CCS aside) — including alerts, which follow the current record state.
                    throw .unexpectedPlaintextRecord(outerType)
                }
                try surface(inner: outerType, content: [UInt8](body), into: &events)
            case .applicationData:
                throw .unexpectedPlaintextRecord(.applicationData)  // no keys to open it (§5.2)
        }
    }

    /// §5.2: opens a protected record and surfaces its §5.4 inner content.
    private mutating func openProtectedRecord(
        header: ArraySlice<UInt8>, body: ArraySlice<UInt8>, into events: inout [TLSRecordEvent]
    ) throws(TLSRecordError) {
        guard var protector = readProtector else {
            throw .unexpectedPlaintextRecord(.applicationData)
        }
        let opened = try protector.open(header: header, body: body)
        readProtector = protector
        guard opened.type != .changeCipherSpec else {
            throw .unexpectedProtectedRecord(.changeCipherSpec)  // §5: CCS is never protected
        }
        if opened.type == .applicationData, readEpoch != .application {
            throw .unexpectedProtectedRecord(.applicationData)  // no app data under hs keys
        }
        try surface(inner: opened.type, content: opened.content, into: &events)
    }

    /// Validates and surfaces one record's content as its event (§5.1 handshake/§6 alert
    /// shapes, application data passed through).
    private mutating func surface(
        inner type: TLSContentType, content: [UInt8], into events: inout [TLSRecordEvent]
    ) throws(TLSRecordError) {
        switch type {
            case .handshake:
                guard !content.isEmpty else {
                    throw .emptyHandshakeRecord  // §5.1: zero-length handshake is forbidden
                }
                sawHandshakeRecord = true
                events.append(.handshake(content))
            case .alert:
                guard content.count == 2 else {
                    throw .malformedAlertRecord  // §6: exactly one 2-octet alert per record
                }
                events.append(
                    .alert(
                        TLSAlert(
                            level: content[0],
                            description: TLSAlertDescription(rawValue: content[1])
                        )
                    )
                )
            case .applicationData:
                events.append(.applicationData(content))  // may be zero-length (§5.1)
            case .changeCipherSpec:
                throw .unexpectedChangeCipherSpec  // funneled off before this point
        }
    }

    /// Drops the §5 / Appendix D.4 unprotected `change_cipher_spec` of exactly one 0x01 octet.
    ///
    /// The tolerance window is bounded: after the first handshake record and before the read
    /// side reaches the application epoch (≈ the peer's Finished). Anything else — a protected
    /// CCS, a malformed body, or one outside the window — aborts with `unexpected_message`.
    private func tolerateChangeCipherSpec(body: ArraySlice<UInt8>) throws(TLSRecordError) {
        guard
            sawHandshakeRecord, readEpoch < .application,
            body.count == 1, body[body.startIndex] == 1
        else {
            throw .unexpectedChangeCipherSpec
        }
    }
}
