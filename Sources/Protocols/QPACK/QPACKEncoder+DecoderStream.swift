//
//  QPACKEncoder+DecoderStream.swift
//  QPACK
//
//  RFC 9204 §4.4 — applying the peer decoder's instruction stream to the encoder. An Insert Count
//  Increment (§4.4.3) advances the known-received count, unblocking those entries for future references.
//  A Section Acknowledgment (§4.4.1) retires the oldest unacknowledged section on its stream and releases
//  the references it held, so the entries it pinned may now be evicted (§2.1.3). A Stream Cancellation
//  (§4.4.2) releases every outstanding section on the stream. A malformed instruction — an Increment of 0
//  or past the inserts made, an acknowledgment for a stream with no outstanding section — is a
//  QPACK_DECODER_STREAM_ERROR. Parsing is incremental: a partial trailing instruction is left unconsumed.
//

internal import HTTPCore

extension QPACKEncoder {
    /// Applies the peer decoder's instruction stream, returning the octets consumed (RFC 9204 §4.4).
    ///
    /// A partial trailing instruction is left for the next call.
    public mutating func applyDecoderInstructions(_ span: RawSpan) throws(QPACKError) -> Int {
        var reader = ByteReader(span)
        var committed = reader.position
        while let first = reader.peek() {
            guard try applyOneDecoderInstruction(&reader, first: first) else {
                break  // truncated — stop at the last complete instruction
            }
            committed = reader.position
        }
        return committed
    }

    /// Applies one decoder-stream instruction, advancing `reader` on success; false (unmoved) if truncated.
    private mutating func applyOneDecoderInstruction(
        _ reader: inout ByteReader, first: UInt8
    ) throws(QPACKError) -> Bool {
        if first & 0x80 != 0 {
            return try applySectionAcknowledgment(&reader)  // §4.4.1
        }
        if first & 0x40 != 0 {
            return try applyStreamCancellation(&reader)  // §4.4.2
        }
        return try applyInsertCountIncrement(&reader)  // §4.4.3
    }

    /// RFC 9204 §4.4.1 — Section Acknowledgment: retire the stream's oldest unacknowledged section and
    /// release its references; an acknowledgment for a stream with none outstanding is a stream error.
    private mutating func applySectionAcknowledgment(
        _ reader: inout ByteReader
    ) throws(QPACKError) -> Bool {
        var probe = reader
        guard let streamID = try decodeStreamID(&probe, prefixBits: 7) else {
            return false
        }
        guard var sections = outstandingSections[streamID], !sections.isEmpty else {
            throw .decoderStreamError("Section Acknowledgment with no outstanding section")
        }
        release(sections.removeFirst().references)
        outstandingSections[streamID] = sections.isEmpty ? nil : sections
        reader = probe
        return true
    }

    /// RFC 9204 §4.4.2 — Stream Cancellation: release every outstanding section on the stream.
    private mutating func applyStreamCancellation(
        _ reader: inout ByteReader
    ) throws(QPACKError) -> Bool {
        var probe = reader
        guard let streamID = try decodeStreamID(&probe, prefixBits: 6) else {
            return false
        }
        if let sections = outstandingSections.removeValue(forKey: streamID) {
            for section in sections {
                release(section.references)
            }
        }
        reader = probe
        return true
    }

    /// RFC 9204 §4.4.3 — Insert Count Increment: advance the known-received count, or fault if it is 0 or
    /// would exceed the inserts actually made.
    private mutating func applyInsertCountIncrement(
        _ reader: inout ByteReader
    ) throws(QPACKError) -> Bool {
        var probe = reader
        switch QPACKInteger.decode(&probe, prefixBits: 6) {
            case .value(let increment):
                guard increment > 0 else {
                    throw .decoderStreamError("Insert Count Increment of 0")
                }
                guard knownReceivedCount + increment <= table.insertCount else {
                    throw .decoderStreamError("Insert Count Increment beyond the inserts made")
                }
                acknowledgeInserts(increment)
                reader = probe
                return true
            case .incomplete:
                return false
            case .overflow:
                throw .decoderStreamError("invalid Insert Count Increment")
        }
    }

    /// Decrements the reference count of each absolute index, freeing fully-released entries for eviction
    /// (RFC 9204 §2.1.3).
    private mutating func release(_ references: [Int]) {
        for absolute in references {
            guard let count = referenceCounts[absolute] else {
                continue
            }
            if count <= 1 {
                referenceCounts[absolute] = nil
            }
            else {
                referenceCounts[absolute] = count - 1
            }
        }
    }

    /// Decodes a Section-Ack / Stream-Cancel stream id, advancing `probe`; nil if truncated, throws on
    /// overflow (RFC 9204 §4.4.1/§4.4.2).
    private func decodeStreamID(
        _ probe: inout ByteReader, prefixBits: Int
    ) throws(QPACKError) -> UInt64? {
        switch QPACKInteger.decode(&probe, prefixBits: prefixBits) {
            case .value(let value):
                return UInt64(value)
            case .incomplete:
                return nil
            case .overflow:
                throw .decoderStreamError("invalid acknowledgment stream id")
        }
    }
}
