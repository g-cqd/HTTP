//
//  HTTP3Connection+Request.swift
//  HTTP3
//
//  RFC 9114 §4 — request-stream handling on a client-initiated bidirectional stream. The valid frame
//  sequence is HEADERS, optional DATA, optional trailing HEADERS (trailers); any other sequence — DATA
//  before HEADERS, a control frame (SETTINGS/GOAWAY/CANCEL_PUSH/MAX_PUSH_ID/PUSH_PROMISE) on a request
//  stream, or a reserved HTTP/2 frame type — is H3_FRAME_UNEXPECTED (§4.1 / §7.2.1). HEADERS are
//  QPACK-decoded (a fault is the connection-level QPACK_DECOMPRESSION_FAILED) and mapped to an
//  HTTPRequest (a malformed message is the stream-level H3_MESSAGE_ERROR). At FIN the request is
//  surfaced; a frame whose length ran past the stream end is H3_FRAME_ERROR (§7.1), and a declared
//  content-length that disagrees with the DATA length is H3_MESSAGE_ERROR (§4.1.2).
//

internal import HTTPCore
internal import QPACK

extension HTTP3Connection {
    /// Processes buffered request-stream bytes: drain frames, then surface the request once FIN closes
    /// the send side.
    mutating func processRequestStream(
        _ streamID: QUICStreamID,
        into events: inout [Event]
    ) throws(HTTP3Error) {
        for frame in try drainFrames(streamID) {
            try handleRequestFrame(streamID, frame)
        }
        guard streams[streamID]?.finReceived == true else {
            return
        }
        try finishRequest(streamID, into: &events)
    }

    /// Validates one request-stream frame against the §4.1 sequence and routes HEADERS / DATA.
    private mutating func handleRequestFrame(
        _ streamID: QUICStreamID,
        _ frame: HTTP3FrameDecoder.Frame
    ) throws(HTTP3Error) {
        if frame.type.isReservedHTTP2Frame {
            throw .connection(
                .h3FrameUnexpected, "a reserved HTTP/2 frame type on a request stream"
            )
        }
        switch frame.type {
            case .headers:
                try handleRequestHeaders(streamID, frame.payload)
            case .data:
                try handleRequestData(streamID, frame.payload)
            case .settings, .goAway, .maxPushID, .cancelPush, .pushPromise:
                throw .connection(.h3FrameUnexpected, "a control frame on a request stream")
            default:
                break  // unknown / grease frame types are ignored (RFC 9114 §9)
        }
    }

    /// Handles a HEADERS frame: the first is the request, a second is trailers (RFC 9114 §4.1).
    private mutating func handleRequestHeaders(
        _ streamID: QUICStreamID,
        _ payload: [UInt8]
    ) throws(HTTP3Error) {
        guard var state = streams[streamID] else {
            return
        }
        guard !state.sawTrailers else {
            throw .connection(.h3FrameUnexpected, "a HEADERS frame after trailers")
        }
        let requiredInsertCount = try requiredInsertCount(of: payload)
        // A request HEADERS section that depends on inserts not yet received is buffered (blocked) until
        // the encoder stream delivers them (RFC 9204 §2.1.2); trailers fall through to a decode error.
        if !state.sawHeaders, requiredInsertCount > decoder.insertCount {
            try bufferBlockedSection(
                streamID,
                payload: payload,
                requiredInsertCount: requiredInsertCount,
                &state
            )
            return
        }
        let fields = try decodeFieldSection(payload)
        // A field section that depended on the dynamic table is acknowledged so the peer encoder learns
        // its entries are no longer referenced and may be evicted (RFC 9204 §4.4.1).
        if requiredInsertCount > 0 {
            acknowledgeSection(streamID)
        }
        if state.sawHeaders {
            // Trailers (RFC 9114 §4.3): validated — no pseudo-header fields, lowercase names only — then
            // discarded, not folded into the request. Shared with HTTP/2 so both engines apply the rule.
            try RequestMapper.validateTrailers(fields) { reason in
                HTTP3Error.stream(streamID, .h3MessageError, reason)
            }
            state.sawTrailers = true
            streams[streamID] = state
            return
        }
        let (request, _) = try HTTP3RequestMapper.makeRequest(from: fields, streamID: streamID)
        state.sawHeaders = true
        state.request = request
        streams[streamID] = state
    }

    /// Handles a DATA frame: appends to the body after HEADERS and before trailers (RFC 9114 §4.1).
    private mutating func handleRequestData(
        _ streamID: QUICStreamID,
        _ payload: [UInt8]
    ) throws(HTTP3Error) {
        guard var state = streams[streamID] else {
            return
        }
        // A buffered blocked HEADERS counts as "HEADERS seen": the field section is on the wire, only its
        // decode is deferred, so DATA legitimately follows it (RFC 9204 §2.1.2).
        guard state.sawHeaders || state.blockedSection != nil else {
            throw .connection(.h3FrameUnexpected, "a DATA frame before HEADERS")
        }
        guard !state.sawTrailers else {
            throw .connection(.h3FrameUnexpected, "a DATA frame after trailers")
        }
        state.body.append(contentsOf: payload)
        guard state.body.count <= limits.maxBodySize else {
            throw .stream(streamID, .h3RequestRejected, "request body exceeds the maximum")
        }
        // Bound the connection's *total* buffered (un-dispatched) request body across all streams, not
        // just per-stream: as in HTTP/2, the engine would otherwise buffer up to the concurrent-stream
        // count × maxBodySize before any stream's FIN dispatches it — a memory-exhaustion vector. Sum the
        // other streams plus this stream's running total (RFC 9114 §4.1; CWE-400/770).
        let otherStreamsBuffered = streams.reduce(0) { sum, entry in
            entry.key == streamID ? sum : sum + entry.value.body.count
        }
        guard otherStreamsBuffered + state.body.count <= limits.maxBodySize else {
            throw .stream(
                streamID,
                .h3ExcessiveLoad,
                "connection request-body buffer exceeds the maximum"
            )
        }
        streams[streamID] = state
    }

    /// Finishes a request at FIN: rejects a dangling partial frame, validates content-length, emits.
    private mutating func finishRequest(
        _ streamID: QUICStreamID,
        into events: inout [Event]
    ) throws(HTTP3Error) {
        guard let state = streams[streamID], !state.requestEmitted else {
            return
        }
        // A non-empty buffer at FIN is a frame whose Length ran past the stream end (RFC 9114 §7.1).
        guard state.buffer.isEmpty else {
            throw .connection(.h3FrameError, "a frame extends past the end of the stream")
        }
        // A stream still blocked on not-yet-received inserts holds its FIN: the request surfaces once the
        // encoder stream unblocks it (`unblockBlockedSections`), not now (RFC 9204 §2.1.2).
        guard state.blockedSection == nil else {
            return
        }
        guard state.sawHeaders, let request = state.request else {
            throw .stream(streamID, .h3MessageError, "request stream closed without HEADERS")
        }
        try validateContentLength(request, bodyCount: state.body.count, streamID: streamID)
        streams[streamID]?.requestEmitted = true
        events.append(.request(streamID: streamID, request: request, body: state.body))
        // The body now belongs to the dispatched event; drop the engine's copy so it no longer counts
        // against the connection buffered-body budget (handleRequestData) — mirrors the HTTP/2 engine.
        streams[streamID]?.body = []
    }

    /// RFC 9114 §4.1.2 — a declared content-length must equal the DATA length; absent is fine.
    private func validateContentLength(
        _ request: HTTPRequest,
        bodyCount: Int,
        streamID: QUICStreamID
    ) throws(HTTP3Error) {
        switch request.headerFields.contentLength {
            case .absent:
                return
            case .invalid:
                throw .stream(streamID, .h3MessageError, "invalid content-length")
            case .length(let declared):
                guard declared == bodyCount else {
                    throw .stream(
                        streamID, .h3MessageError, "content-length does not match the body"
                    )
                }
        }
    }

    /// The Required Insert Count a field section's prefix encodes (RFC 9204 §4.5.1), mapping a fault to
    /// the connection-level QPACK_DECOMPRESSION_FAILED — used to decide whether the section is owed a
    /// Section Acknowledgment.
    private func requiredInsertCount(of payload: [UInt8]) throws(HTTP3Error) -> Int {
        let result: Result<Int, QPACKError> = payload.withUnsafeBytes { raw in
            Result { () throws(QPACKError) in try decoder.requiredInsertCount(of: raw.bytes) }
        }
        switch result {
            case .success(let value):
                return value
            case .failure(let error):
                throw .connection(qpack: error.code, error.reason)
        }
    }

    /// QPACK-decodes a request field section, mapping a fault to the connection-level
    /// QPACK_DECOMPRESSION_FAILED (RFC 9204 §2.2).
    private func decodeFieldSection(_ payload: [UInt8]) throws(HTTP3Error) -> [HeaderField] {
        let result: Result<[HeaderField], QPACKError> = payload.withUnsafeBytes { raw in
            Result { () throws(QPACKError) in try decoder.decode(raw.bytes) }
        }
        switch result {
            case .success(let fields):
                return fields
            case .failure(let error):
                throw .connection(qpack: error.code, error.reason)
        }
    }

    // MARK: Blocked streams (RFC 9204 §2.1.2)

    /// Acknowledges a field section that used the dynamic table so the peer encoder learns its entries
    /// are no longer referenced and may be evicted (RFC 9204 §4.4.1).
    private mutating func acknowledgeSection(_ streamID: QUICStreamID) {
        actions.append(
            .send(
                stream: .role(.qpackDecoder),
                bytes: QPACKInstructions.sectionAcknowledgment(streamID: streamID.rawValue),
                fin: false
            )
        )
    }

    /// Buffers a request HEADERS section that references inserts not yet received, to be decoded once the
    /// encoder stream delivers them (RFC 9204 §2.1.2).
    ///
    /// More streams blocked at once than the advertised limit permits is a QPACK_DECOMPRESSION_FAILED
    /// connection error — the peer encoder broke its own bound.
    private mutating func bufferBlockedSection(
        _ streamID: QUICStreamID,
        payload: [UInt8],
        requiredInsertCount: Int,
        _ state: inout StreamState
    ) throws(HTTP3Error) {
        let alreadyBlocked = streams.values.reduce(0) { $0 + ($1.blockedSection == nil ? 0 : 1) }
        guard alreadyBlocked < localSettings.qpackBlockedStreams else {
            throw .connection(
                qpack: .decompressionFailed, "more blocked streams than the limit permits"
            )
        }
        state.blockedSection = (payload, requiredInsertCount)
        streams[streamID] = state
    }

    /// After the encoder stream raises the insert count, decodes every buffered request whose Required
    /// Insert Count is now satisfied (RFC 9204 §2.1.2).
    ///
    /// A malformed unblocked request resets only that stream — mirroring ``receive``'s catch — so it never
    /// strands its siblings; a QPACK decompression fault is connection-fatal and propagates.
    mutating func unblockBlockedSections(into events: inout [Event]) throws(HTTP3Error) {
        let ready = streams.compactMap { entry -> QUICStreamID? in
            guard let blocked = entry.value.blockedSection,
                blocked.requiredInsertCount <= decoder.insertCount
            else {
                return nil
            }
            return entry.key
        }
        for streamID in ready {
            do {
                try decodeBlockedSection(streamID, into: &events)
            }
            catch {
                guard error.isConnectionError else {
                    actions.append(.resetStream(streamID: streamID, errorCode: error.code))
                    streams[streamID] = nil
                    chargeStreamReset()
                    continue
                }
                throw error
            }
        }
    }

    /// Decodes a now-unblocked request section, acknowledges it, and surfaces the request if its FIN
    /// already arrived while it was blocked (RFC 9204 §2.1.2 / §4.4.1).
    private mutating func decodeBlockedSection(
        _ streamID: QUICStreamID, into events: inout [Event]
    ) throws(HTTP3Error) {
        guard var state = streams[streamID], let blocked = state.blockedSection else {
            return
        }
        let fields = try decodeFieldSection(blocked.payload)
        acknowledgeSection(streamID)  // a blocked section always referenced the dynamic table
        let (request, _) = try HTTP3RequestMapper.makeRequest(from: fields, streamID: streamID)
        state.sawHeaders = true
        state.request = request
        state.blockedSection = nil
        streams[streamID] = state
        if state.finReceived {
            try finishRequest(streamID, into: &events)
        }
    }
}
