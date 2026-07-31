//
//  HTTP3Connection+Streams.swift
//  HTTP3
//
//  RFC 9114 §6 — the per-stream handlers for the connection engine. Unidirectional streams are
//  classified from their §6.2 Stream Type byte (the control / QPACK encoder / QPACK decoder singletons,
//  push streams a server must refuse, and tolerated reserved types). The control stream (§6.2.1) must
//  open with SETTINGS and then carries GOAWAY / CANCEL_PUSH / MAX_PUSH_ID; the QPACK streams (§4.2) are
//  scanned only for violations (the dynamic table is disabled). A closed critical stream is fatal. The
//  request-stream handler (§4) is filled in by HTTP3Connection+Streams adjacent code in P5.
//

internal import HTTPCore
internal import QPACK

extension HTTP3Connection {
    // MARK: Unidirectional stream classification (RFC 9114 §6.2)

    /// Reads the §6.2 Stream Type from a freshly opened unidirectional stream and assigns its role,
    /// then dispatches any buffered remainder to the role's handler.
    mutating func classifyUniStream(
        _ streamID: QUICStreamID,
        into events: inout [Event]
    ) throws(HTTP3Error) {
        // the Stream Type varint has not fully arrived yet
        guard let streamType = consumeStreamType(streamID) else {
            return
        }
        let kind = try assignUniStreamRole(
            streamID, role: HTTP3StreamRole(streamType: streamType)
        )
        // Route the buffered remainder straight to the now-known kind's handler rather than back
        // through `dispatch`, so unidirectional classification never re-enters it (no recursion).
        try dispatchClassified(streamID, kind: kind, into: &events)
    }

    /// Reads and consumes the §6.2 Stream Type varint, or returns nil while it is still arriving.
    ///
    /// The varint is decoded in place out of the stream's buffer and consumed by advancing the read
    /// cursor — the buffer itself is never shifted, and never copied to be read (audit CR-F18).
    private mutating func consumeStreamType(_ streamID: QUICStreamID) -> UInt64? {
        guard var taken = streams.takeBuffer(of: streamID) else {
            return nil
        }
        let decoded: (type: UInt64, consumed: Int)? = taken.buffer.withUnsafeBytes { raw in
            var reader = ByteReader(raw, startingAt: taken.start)
            guard let type = QUICVarint.decode(&reader) else {
                return nil
            }
            return (type, reader.position)
        }
        streams.restoreBuffer(
            &taken.buffer, of: streamID, consumedTo: decoded?.consumed ?? taken.start
        )
        return decoded?.type
    }

    /// Assigns a unidirectional stream's role, enforcing the critical-stream singletons (§6.2.1) and
    /// refusing a client-initiated push stream (§6.2.2).
    ///
    /// Returns the kind the stream now has, so the caller can dispatch without holding a copy of the
    /// record — a live copy would share the receive buffer and make the handler's first touch of it a
    /// copy-on-write copy.
    private mutating func assignUniStreamRole(
        _ streamID: QUICStreamID,
        role: HTTP3StreamRole
    ) throws(HTTP3Error) -> StreamKind {
        switch role {
            case .control:
                guard peerControlStream == nil else {
                    throw .connection(.h3StreamCreationError, "a second control stream")
                }
                peerControlStream = streamID
            case .qpackEncoder:
                guard peerQpackEncoderStream == nil else {
                    throw .connection(.h3StreamCreationError, "a second QPACK encoder stream")
                }
                peerQpackEncoderStream = streamID
            case .qpackDecoder:
                guard peerQpackDecoderStream == nil else {
                    throw .connection(.h3StreamCreationError, "a second QPACK decoder stream")
                }
                peerQpackDecoderStream = streamID
            case .push:
                throw .connection(.h3StreamCreationError, "a server must not receive a push stream")
            case .request, .reserved:
                break  // unknown / reserved types are tolerated; data discarded
        }
        let kind = Self.kind(of: role)
        streams[streamID]?.kind = kind
        return kind
    }

    /// The engine's stream kind for a §6.2 unidirectional stream type.
    private static func kind(of role: HTTP3StreamRole) -> StreamKind {
        switch role {
            case .control:
                .control
            case .qpackEncoder:
                .qpackEncoder
            case .qpackDecoder:
                .qpackDecoder
            case .push, .request, .reserved:
                .reserved
        }
    }

    // MARK: Control stream (RFC 9114 §6.2.1)

    /// Processes the control stream: SETTINGS first, then GOAWAY / CANCEL_PUSH / MAX_PUSH_ID.
    ///
    /// Its closure is H3_CLOSED_CRITICAL_STREAM (§6.2.1).
    mutating func processControlStream(
        _ streamID: QUICStreamID,
        into events: inout [Event]
    ) throws(HTTP3Error) {
        try walkFrames(streamID, sink: .control, into: &events)
        if streams[streamID]?.finReceived == true {
            throw .connection(.h3ClosedCriticalStream, "the control stream was closed")
        }
    }

    /// Validates and applies one control-stream frame (RFC 9114 §6.2.1 / §7.2).
    private mutating func handleControlFrame(
        _ frame: HTTP3FrameView,
        into events: inout [Event]
    ) throws(HTTP3Error) {
        guard peerSettingsReceived else {
            guard frame.type == .settings else {
                throw .connection(.h3MissingSettings, "the first control frame is not SETTINGS")
            }
            try applyPeerSettings(frame.payload)
            peerSettingsReceived = true
            return
        }
        if frame.type.isReservedHTTP2Frame {
            throw .connection(.h3FrameUnexpected, "a reserved HTTP/2 frame type")
        }
        switch frame.type {
            case .settings:
                throw .connection(.h3FrameUnexpected, "a second SETTINGS frame")
            case .data, .headers, .pushPromise:
                throw .connection(.h3FrameUnexpected, "a request frame on the control stream")
            case .goAway:
                try handleGoAway(frame.payload, into: &events)
            case .cancelPush:
                try handleCancelPush(frame.payload)
            case .maxPushID:
                try handleMaxPushID(frame.payload)
            default:
                break  // unknown / grease frame types are ignored (RFC 9114 §9)
        }
    }

    /// RFC 9114 §5.2 / §7.2.6 — a received GOAWAY id must not increase.
    private mutating func handleGoAway(
        _ payload: RawSpan, into events: inout [Event]
    ) throws(HTTP3Error) {
        guard let id = singleVarint(payload) else {
            throw .connection(.h3FrameError, "malformed GOAWAY")
        }
        if let last = lastGoAwayID, id > last {
            throw .connection(.h3IdError, "GOAWAY identifier increased")
        }
        lastGoAwayID = id
        events.append(.goAway(streamID: QUICStreamID(id)))
    }

    /// RFC 9114 §7.2.3 — a CANCEL_PUSH push id must be below the MAX_PUSH_ID we permitted.
    private func handleCancelPush(_ payload: RawSpan) throws(HTTP3Error) {
        guard let pushID = singleVarint(payload) else {
            throw .connection(.h3FrameError, "malformed CANCEL_PUSH")
        }
        guard pushID < (maxPushID ?? 0) else {
            throw .connection(.h3IdError, "CANCEL_PUSH for a push id above MAX_PUSH_ID")
        }
    }

    /// RFC 9114 §7.2.7 — a MAX_PUSH_ID must not decrease.
    private mutating func handleMaxPushID(_ payload: RawSpan) throws(HTTP3Error) {
        guard let id = singleVarint(payload) else {
            throw .connection(.h3FrameError, "malformed MAX_PUSH_ID")
        }
        if let current = maxPushID, id < current {
            throw .connection(.h3IdError, "MAX_PUSH_ID decreased")
        }
        maxPushID = id
    }

    // MARK: QPACK streams (RFC 9204 §4.2)

    /// Scans the peer's QPACK encoder stream for violations; its closure is a critical-stream error.
    mutating func processQpackEncoderStream(
        _ streamID: QUICStreamID, into events: inout [Event]
    ) throws(HTTP3Error) {
        try applyEncoderStream(streamID, into: &events)
        if streams[streamID]?.finReceived == true {
            throw .connection(.h3ClosedCriticalStream, "the QPACK encoder stream was closed")
        }
    }

    /// Scans the peer's QPACK decoder stream for violations; its closure is a critical-stream error.
    mutating func processQpackDecoderStream(_ streamID: QUICStreamID) throws(HTTP3Error) {
        try parseDecoderStream(streamID)
        if streams[streamID]?.finReceived == true {
            throw .connection(.h3ClosedCriticalStream, "the QPACK decoder stream was closed")
        }
    }

    /// Applies the peer's encoder-stream inserts into the decoder's dynamic table (RFC 9204 §4.3),
    /// acknowledges them with an Insert Count Increment on our decoder stream (§4.4.3), then decodes any
    /// request sections those inserts just unblocked (§2.1.2).
    private mutating func applyEncoderStream(
        _ streamID: QUICStreamID, into events: inout [Event]
    ) throws(HTTP3Error) {
        guard var taken = streams.takeBuffer(of: streamID) else {
            return
        }
        let result: Result<(consumed: Int, inserts: Int), QPACKError> =
            taken.buffer.withUnsafeBytes { raw in
                Result { () throws(QPACKError) in
                    // The instructions are applied straight out of the stream's buffer, from the read
                    // cursor — `applyEncoderInstructions` already takes a `RawSpan` (RFC 9204 §4.3).
                    try decoder.applyEncoderInstructions(
                        raw.bytes.extracting(taken.start ..< taken.buffer.count)
                    )
                }
            }
        switch result {
            case .success(let applied):
                streams.restoreBuffer(
                    &taken.buffer, of: streamID, consumedTo: taken.start + applied.consumed
                )
                guard applied.inserts > 0 else {
                    return
                }
                actions.append(
                    .send(
                        stream: .role(.qpackDecoder),
                        bytes: QPACKInstructions.insertCountIncrement(applied.inserts),
                        fin: false
                    )
                )
                try unblockBlockedSections(into: &events)
            case .failure(let error):
                throw .connection(qpack: error.code, error.reason)
        }
    }

    /// Applies the peer decoder's acknowledgments to our response encoder (RFC 9204 §4.4): an Insert
    /// Count Increment advances the encoder's known-received count; Section Acknowledgment and Stream
    /// Cancellation are consumed.
    ///
    /// An Increment of 0, or one beyond what we inserted, is a critical-stream error.
    private mutating func parseDecoderStream(_ streamID: QUICStreamID) throws(HTTP3Error) {
        guard var taken = streams.takeBuffer(of: streamID) else {
            return
        }
        let result: Result<Int, QPACKError> = taken.buffer.withUnsafeBytes { raw in
            Result { () throws(QPACKError) in
                // Read from the cursor, in place: `applyDecoderInstructions` already takes a
                // `RawSpan` (RFC 9204 §4.4), so the buffer never needed shifting to be parsed.
                try encoder.applyDecoderInstructions(
                    raw.bytes.extracting(taken.start ..< taken.buffer.count)
                )
            }
        }
        switch result {
            case .success(let consumed):
                streams.restoreBuffer(
                    &taken.buffer, of: streamID, consumedTo: taken.start + consumed
                )
            case .failure(let error):
                throw .connection(qpack: error.code, error.reason)
        }
    }

    // MARK: Helpers

    /// Where a walked frame is handled: the §6.2.1 control stream, or a §4 request stream.
    enum FrameSink {
        case control
        case request
    }

    /// Walks a stream's buffered octets one frame at a time, handling each frame while its payload is
    /// still BORROWED from that buffer (audit CR-F18).
    ///
    /// The buffer is taken out of the table for the walk. The handlers mutate the connection — they
    /// decode field sections, append actions and events, retire streams — while a `RawSpan` into the
    /// buffer is live, and Swift's exclusivity rules forbid that on state the table still holds. The
    /// take/restore pair separates the borrow from the mutation without separating them in time, and
    /// lets each payload stay exactly where QUIC delivered it.
    ///
    /// Consumed octets are handed back as a cursor, not shifted out. A frame that is still arriving
    /// leaves the cursor before it, so it is re-read from the same place once the rest lands (RFC 9114
    /// §7.1 — on a QUIC stream that is the normal case, not an edge).
    mutating func walkFrames(
        _ streamID: QUICStreamID,
        sink: FrameSink,
        into events: inout [Event]
    ) throws(HTTP3Error) {
        guard var taken = streams.takeBuffer(of: streamID) else {
            return
        }
        let outcome: Result<Int, HTTP3Error> = taken.buffer.withUnsafeBytes { raw in
            Result { () throws(HTTP3Error) in
                var reader = ByteReader(raw, startingAt: taken.start)
                // An index-based `while` over the cursor, never a `for-in` over a span-derived
                // sequence: the shape every span-borrowing scan in the package uses (see
                // `MultipartParser`), so the debug-build allocation oracles are not charged for
                // `IndexingIterator.next()` (task #29 sweep).
                while let framing = try frameDecoder.nextFrameRange(&reader) {
                    let frame = HTTP3FrameView(
                        type: framing.type,
                        payload: reader.slice(in: framing.payload)
                    )
                    switch sink {
                        case .control:
                            try handleControlFrame(frame, into: &events)
                        case .request:
                            try handleRequestFrame(streamID, frame)
                    }
                }
                return reader.position
            }
        }
        switch outcome {
            case .success(let consumed):
                streams.restoreBuffer(&taken.buffer, of: streamID, consumedTo: consumed)
            case .failure(let error):
                // The stream is failing: a connection error closes everything, and a stream error
                // drops this record in `receive`'s catch. Either way its buffer goes with it.
                throw error
        }
    }

    /// Decodes exactly one varint that must occupy the whole payload, else nil (malformed).
    private func singleVarint(_ payload: RawSpan) -> UInt64? {
        var reader = ByteReader(payload)
        guard let value = QUICVarint.decode(&reader), reader.isAtEnd else {
            return nil
        }
        return value
    }

    /// Applies a received SETTINGS payload to ``remoteSettings`` (RFC 9114 §7.2.4).
    private mutating func applyPeerSettings(_ payload: RawSpan) throws(HTTP3Error) {
        // §7.2.4 is parsed straight out of the stream's buffer: `HTTP3Settings.apply` already takes a
        // `RawSpan`, so the payload never needed to be an `[UInt8]` to be read.
        var settings = HTTP3Settings()
        try settings.apply(payload)
        remoteSettings = settings
        // The peer's advertised QPACK capacity enables our response encoder's dynamic table, bounded by
        // our own memory limit. The encoder references only acknowledged inserts, so it never blocks the
        // peer regardless of the peer's blocked-streams limit (RFC 9204 §3.2.3 / §2.1.2).
        let cap = min(remoteSettings.qpackMaxTableCapacity, Self.defaultQpackMaxTableCapacity)
        encoder.enableDynamicTable(
            capacity: cap,
            blockedStreams: remoteSettings.qpackBlockedStreams
        )
    }
}
