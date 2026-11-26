//
//  TLSRecordDeframer.swift
//  HTTPTLS
//
//  RFC 8446 §5.1 — the record splitter shared by every connection role and drive (server async,
//  server synchronous, client): cuts exactly one record out of the feed (or the cross-feed
//  holdback) and runs it through the record layer. ONE record-boundary implementation.
//

/// Splits inbound octets into whole TLS records across feeds (RFC 8446 §5.1).
struct TLSRecordDeframer: Sendable {
    /// Octets of a record whose tail has not arrived yet.
    private var holdback: [UInt8] = []

    /// Creates a splitter whose holdback can carry one maximal ciphertext record.
    init() {
        holdback.reserveCapacity(TLSRecordLimits.headerLength + TLSRecordLimits.maxCiphertextLength)
    }

    /// Cuts one record from `bytes` at `cursor` (or completes the held-back one) and feeds it to
    /// `record`; nil when only a partial record remains (stashed for the next feed).
    mutating func pump(
        _ bytes: [UInt8],
        cursor: inout Int,
        through record: inout TLSRecordLayer
    ) throws(TLSHandshakeError) -> [TLSRecordEvent]? {
        if holdback.isEmpty {
            guard cursor < bytes.endIndex else {
                return nil
            }
            let needed = Self.recordLengthNeeded(bytes[cursor...])
            guard bytes.endIndex - cursor >= needed else {
                holdback.append(contentsOf: bytes[cursor...])
                cursor = bytes.endIndex
                return nil
            }
            let slice = bytes[cursor ..< cursor + needed]
            cursor += needed
            return try Self.feed(slice, to: &record)
        }
        topUp(bytes, cursor: &cursor)  // header first, then the body
        let needed = Self.recordLengthNeeded(holdback[...])
        guard holdback.count >= TLSRecordLimits.headerLength, holdback.count >= needed else {
            return nil
        }
        let events = try Self.feed(holdback[..<needed], to: &record)
        holdback.removeAll(keepingCapacity: true)
        return events
    }

    /// Tops the holdback up to the record header, re-derives the full length, then tops up
    /// to the whole record (never past it).
    private mutating func topUp(_ bytes: [UInt8], cursor: inout Int) {
        for _ in 0 ..< 2 {  // once for the header, once for the body it reveals
            let needed = Self.recordLengthNeeded(holdback[...])
            let take = min(needed - holdback.count, bytes.endIndex - cursor)
            guard take > 0 else {
                return
            }
            holdback.append(contentsOf: bytes[cursor ..< cursor + take])
            cursor += take
        }
    }

    /// How many octets the record at the slice's head occupies.
    ///
    /// The header alone until the length field is visible — or when the header is already
    /// condemnable (an unknown §5.1 content type, a length past the §5.2 cap), in which
    /// case the bare header is fed and the record layer's own `validateHeader` raises the
    /// right error NOW rather than after a phantom body. The content-type check is what
    /// makes a cleartext mis-dial (an HTTP request where a ClientHello belongs) die at its
    /// first five octets instead of stalling for a body the peer will never send.
    private static func recordLengthNeeded(_ bytes: ArraySlice<UInt8>) -> Int {
        let base = bytes.startIndex
        guard bytes.count >= TLSRecordLimits.headerLength else {
            return TLSRecordLimits.headerLength
        }
        guard TLSContentType(rawValue: bytes[base]) != nil else {
            return TLSRecordLimits.headerLength  // fed bare; unknown_content_type, fail fast
        }
        let bodyLength = Int(bytes[base + 3]) << 8 | Int(bytes[base + 4])
        guard bodyLength <= TLSRecordLimits.maxCiphertextLength else {
            return TLSRecordLimits.headerLength  // fed bare; the layer throws record_overflow
        }
        return TLSRecordLimits.headerLength + bodyLength
    }

    /// Runs one record through the layer, converting its failures to the funnel's currency.
    private static func feed(
        _ slice: ArraySlice<UInt8>,
        to record: inout TLSRecordLayer
    ) throws(TLSHandshakeError) -> [TLSRecordEvent] {
        do {
            return try record.receive(slice)
        }
        catch {
            throw .record(error)
        }
    }
}
