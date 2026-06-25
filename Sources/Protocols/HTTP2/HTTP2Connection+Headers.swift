//
//  HTTP2Connection+Headers.swift
//  HTTP2
//
//  RFC 9113 — the HEADERS / CONTINUATION field-block lifecycle, split out of HTTP2Connection.swift
//  for navigability (mirroring +FlowControl / +Response / +AbuseBudget): fragment assembly (§6.10)
//  into a complete block, HPACK decode (§4.3), the new-stream checks (client-initiated odd id,
//  monotonic id with §5.1 close-reason scoping, self-dependency §5.3.1, the §5.1.2 concurrency cap),
//  request mapping (§8.3) including the Extended CONNECT tunnel (RFC 8441 §4), and trailing-HEADERS
//  validation (§8.1). `receiveHeaders`/`receiveContinuation` are internal so the frame dispatcher in
//  the main file can call them — the same arrangement the other `receive*` handlers already use.
//

internal import HPACK
internal import HTTPCore

extension HTTP2Connection {
    mutating func receiveHeaders(
        _ frame: HTTP2FrameDecoder.Frame,
        into events: inout [Event]
    ) throws(HTTP2Error) {
        let fragment = try HTTP2HeadersFrame.fieldBlockFragment(
            frame.payload,
            flags: frame.header.flags
        )
        pendingHeadersEndStream = frame.header.flags.contains(.endStream)
        pendingHeadersDependency = HTTP2HeadersFrame.priorityDependency(
            frame.payload,
            flags: frame.header.flags
        )
        let outcome = try accumulator.begin(
            streamID: frame.header.streamID,
            fragment: fragment,
            endHeaders: frame.header.flags.contains(.endHeaders)
        )
        if case .complete(let streamID, let block) = outcome {
            try completeHeaderBlock(streamID, block: block, into: &events)
        }
    }

    mutating func receiveContinuation(
        _ frame: HTTP2FrameDecoder.Frame,
        into events: inout [Event]
    ) throws(HTTP2Error) {
        let outcome = try accumulator.append(
            streamID: frame.header.streamID,
            fragment: frame.payload,
            endHeaders: frame.header.flags.contains(.endHeaders)
        )
        if case .complete(let streamID, let block) = outcome {
            try completeHeaderBlock(streamID, block: block, into: &events)
        }
    }

    private mutating func completeHeaderBlock(
        _ streamID: HTTP2StreamID,
        block: [UInt8],
        into events: inout [Event]
    ) throws(HTTP2Error) {
        let endStream = pendingHeadersEndStream
        let fields = try decodeHeaderBlock(block)  // always decode, to keep the HPACK table in sync

        // A second HEADERS block on an already-open stream is trailers (RFC 9113 §8.1).
        if streams[streamID] != nil {
            try applyTrailers(streamID, fields: fields, endStream: endStream, into: &events)
            return
        }
        guard streamID.isClientInitiated else {
            throw .connection(.protocolError, "client used a non-odd stream identifier")
        }
        guard streamID > lastPeerStreamID else {
            // Reusing a stream id with HEADERS is scoped by how that stream closed (RFC 9113 §5.1): an
            // id closed by END_STREAM cannot reopen → a *connection* error STREAM_CLOSED; one closed by
            // RST_STREAM keeps the lenient survivable *stream* error (audit F1); a never-opened smaller
            // id is the §5.1.1 "unexpected identifier" connection PROTOCOL_ERROR.
            switch closeReason(of: streamID) {
                case .endStream:
                    throw .connection(.streamClosed, "HEADERS reusing an END_STREAM-closed stream")
                case .reset:
                    throw .stream(streamID, .streamClosed, "HEADERS on a reset stream")
                case nil:
                    throw .connection(.protocolError, "stream identifier did not increase")
            }
        }
        lastPeerStreamID = streamID
        // A stream MUST NOT depend on itself (RFC 9113 §5.3.1, carried from RFC 7540). Decoding above
        // kept the HPACK table in sync, so rejecting just this stream leaves the connection usable.
        if pendingHeadersDependency == streamID {
            throw .stream(streamID, .protocolError, "stream depends on itself")
        }
        // Refuse a stream past the concurrency cap (RFC 9113 §5.1.2); the block was decoded above so
        // the dynamic table stays in sync. RST_STREAM(REFUSED_STREAM) keeps the connection alive.
        guard streams.count < maxConcurrentStreams else {
            writer.writeRstStream(streamID, code: .refusedStream)
            // A server-emitted REFUSED_STREAM is charged like any other engine reset: flooding new
            // HEADERS past the concurrency cap would otherwise drive unbounded RST emission + HPACK
            // decode work without tripping the Rapid-Reset / MadeYouReset budget (CVE-2023-44487 /
            // CVE-2025-8671). HPACK stays in sync because the block was already decoded above.
            try chargeStreamReset()
            return
        }
        let (request, connectProtocol) = try HTTP2RequestMapper.makeRequest(
            from: fields,
            streamID: streamID
        )
        var stream = HTTP2Stream(id: streamID)
        try stream.receiveHeaders(endStream: endStream)
        var record = StreamRecord(
            stream: stream,
            request: request,
            body: [],
            sendWindow: HTTP2FlowControlWindow(initialSize: remoteSettings.initialWindowSize),
            receiveWindow: localSettings.initialWindowSize
        )
        // Cache the request's RFC 9218 §4 urgency now so a congested connection's flusher can release
        // this stream's DATA ahead of less-urgent streams (HTTP2Connection+FlowControl.flushAll). An
        // absent or unparseable `Priority` field falls back to the default urgency (§4.1).
        record.urgency = request.priority?.urgency ?? HTTPPriority.defaultUrgency
        // An Extended CONNECT (RFC 8441 §4) opens a tunnel rather than a request: surface it for the
        // driver to accept, and route this stream's DATA as opaque tunnel bytes from here on.
        if let connectProtocol {
            guard localSettings.enableConnectProtocol else {
                throw .stream(streamID, .protocolError, "Extended CONNECT was not enabled")
            }
            record.isTunnel = true
            streams[streamID] = record
            events.append(
                .extendedConnect(streamID: streamID, request: request, protocol: connectProtocol)
            )
            return
        }
        streams[streamID] = record
        if endStream {
            try emitRequest(streamID, into: &events)
        }
    }

    /// Applies a trailing HEADERS block (trailers, RFC 9113 §8.1) — it must end the stream and carry
    /// no pseudo-header fields (§8.1.2.1) with only lowercase names (§8.2.1); both are malformed and
    /// scoped as a *stream* error, like the request path (not silently accepted).
    private mutating func applyTrailers(
        _ streamID: HTTP2StreamID,
        fields: [HPACKField],
        endStream: Bool,
        into events: inout [Event]
    ) throws(HTTP2Error) {
        guard var record = streams.removeValue(forKey: streamID) else {
            return
        }
        do {
            // The state machine first: a frame on a closed stream is STREAM_CLOSED (§5.1) and trailers
            // without END_STREAM is a §8.1 stream PROTOCOL_ERROR — both take precedence over the field
            // checks below, so the §5.1 error code is reported for a closed stream.
            try record.stream.receiveHeaders(endStream: endStream)
        }
        catch {
            streams[streamID] = record
            throw error
        }
        // Validate the accepted trailers: no pseudo-header fields, lowercase names only
        // (RFC 9113 §8.1.2.1 / §8.2.1) — a malformed trailer is a stream error, like the request path.
        // Shared with HTTP/3 (`RequestMapper.validateTrailers`) so both engines apply the same rule.
        try RequestMapper.validateTrailers(fields) { reason in
            HTTP2Error.stream(streamID, .protocolError, reason)
        }
        streams[streamID] = record
        if endStream { try emitRequest(streamID, into: &events) }
    }
}
