//
//  HTTP2Connection+Response.swift
//  HTTP2
//
//  RFC 9113 §8.3.2 — the server-response half of the connection engine: encoding an HTTPResponse into
//  a HEADERS frame (`:status` first, then the fields) and releasing its body through the send-side
//  flow controller. Kept in its own file so HTTP2Connection.swift stays focused on inbound state.
//

internal import HPACK
public import HTTPCore

extension HTTP2Connection {
    /// Queues a response on `streamID`: a HEADERS frame and, if present, DATA frames (RFC 9113 §8.3.2).
    ///
    /// The header block is HPACK-encoded with `:status` first; the body is split into DATA frames no
    /// larger than the peer's SETTINGS_MAX_FRAME_SIZE, with END_STREAM on the final frame. The stream
    /// is advanced through its §5.1 state machine and dropped once closed.
    public mutating func respond(
        to streamID: HTTP2StreamID,
        _ response: HTTPResponse,
        body: [UInt8] = []
    ) throws(HTTP2Error) {
        guard var record = streams.removeValue(forKey: streamID) else {
            throw .connection(.internalError, "response for an unknown stream")
        }
        let hasBody = !body.isEmpty
        // Advance the state machine before touching the encoder, so a bad state never desyncs HPACK.
        try record.stream.sendHeaders(endStream: !hasBody)
        let block = encodeResponseSection(response)
        var headerFlags: HTTP2FrameFlags = [.endHeaders]
        if !hasBody { headerFlags.insert(.endStream) }
        writer.writeFrame(.headers, flags: headerFlags, streamID: streamID, payload: block)
        if hasBody {
            // The body is logically sent now (END_STREAM); its octets are released as the connection
            // and stream send windows allow (RFC 9113 §6.9), the remainder awaiting a WINDOW_UPDATE.
            try record.stream.sendData(endStream: true)
            record.pending = body
            record.pendingEndStream = true
        }
        flushStream(streamID, &record)
    }

    /// Begins a *streaming* response on `streamID`: queues the HEADERS frame **without** END_STREAM,
    /// leaving the stream open for incremental DATA (RFC 9113 §8.1).
    ///
    /// The driver then pumps body chunks with ``sendBodyChunk(to:_:)`` and ends with ``endStream(to:)``;
    /// the body is flow-controlled exactly like a buffered response (§6.9). Throws if the stream is
    /// unknown or cannot send HEADERS in its current state. This is the sans-I/O foundation for native
    /// HTTP/2 response streaming: it only buffers and flushes, so it cannot itself deadlock — the
    /// driver's producer/window coordination (HTTPServer+HTTP2) is what makes the wire-level streaming
    /// bounded and deadlock-free.
    public mutating func respondHeaders(
        to streamID: HTTP2StreamID,
        _ response: HTTPResponse
    ) throws(HTTP2Error) {
        guard var record = streams.removeValue(forKey: streamID) else {
            throw .connection(.internalError, "streaming response for an unknown stream")
        }
        do {
            try record.stream.sendHeaders(endStream: false)
        }
        catch {
            streams[streamID] = record
            throw error
        }
        let block = encodeResponseSection(response)
        writer.writeFrame(.headers, flags: .endHeaders, streamID: streamID, payload: block)
        streams[streamID] = record
    }

    /// Appends a response-body chunk to a streaming response and releases what the send windows allow,
    /// the remainder waiting in the stream's pending buffer for a WINDOW_UPDATE (RFC 9113 §6.9).
    ///
    /// No END_STREAM is set — the stream stays open until ``endStream(to:)``. Throws if the stream is
    /// unknown or cannot send DATA in its current state.
    public mutating func sendBodyChunk(
        to streamID: HTTP2StreamID,
        _ chunk: [UInt8]
    ) throws(HTTP2Error) {
        guard var record = streams.removeValue(forKey: streamID) else {
            throw .connection(.internalError, "body chunk for an unknown stream")
        }
        do {
            try record.stream.sendData(endStream: false)
        }
        catch {
            streams[streamID] = record
            throw error
        }
        record.pending.append(contentsOf: chunk)
        flushStream(streamID, &record)
    }

    /// Ends a streaming response: marks END_STREAM on the final DATA and flushes (RFC 9113 §8.1).
    ///
    /// If buffered body remains, END_STREAM rides its last DATA frame (deferred past an exhausted window
    /// until a WINDOW_UPDATE); if nothing is buffered, an empty END_STREAM DATA frame ends the stream now
    /// (a 0-length DATA consumes no window). Throws if the stream is unknown or cannot send DATA here.
    public mutating func endStream(to streamID: HTTP2StreamID) throws(HTTP2Error) {
        guard var record = streams.removeValue(forKey: streamID) else {
            throw .connection(.internalError, "endStream for an unknown stream")
        }
        do {
            try record.stream.sendData(endStream: true)
        }
        catch {
            streams[streamID] = record
            throw error
        }
        record.pendingEndStream = true
        guard record.pendingOffset >= record.pending.count else {
            flushStream(streamID, &record)  // END_STREAM rides the final buffered DATA frame
            return
        }
        writer.writeData(streamID: streamID, endStream: true, [UInt8]()[...])
        guard record.stream.state == .closed else {
            streams[streamID] = record
            return
        }
        // Closed cleanly via the empty END_STREAM: record the close reason so a later frame on this id
        // is scoped per RFC 9113 §5.1 — matching flushStream's clean-close bookkeeping. Without it a
        // HEADERS reuse of this id would read as an idle-stream PROTOCOL_ERROR, not STREAM_CLOSED.
        streams[streamID] = nil
        markStreamClosed(streamID, reason: .endStream)
    }

    /// The number of response-body octets buffered (window-blocked) for `streamID` — the backpressure
    /// signal a streaming driver gates its producer on, so memory stays bounded (RFC 9113 §6.9).
    public func pendingBacklog(of streamID: HTTP2StreamID) -> Int {
        guard let record = streams[streamID] else {
            return 0
        }
        return record.pending.count - record.pendingOffset
    }

    /// Aborts a streaming response with RST_STREAM (RFC 9113 §6.4), discarding any buffered DATA.
    ///
    /// Used when the body producer fails partway, so the peer sees an incomplete response rather than a
    /// truncated-but-clean one. A no-op for an unknown stream.
    ///
    /// A server-*emitted* RST_STREAM counts against the reset budget too — otherwise an attacker
    /// provokes unbounded resets the client never sends, bypassing the Rapid-Reset defense: MadeYouReset
    /// (CVE-2025-8671) — matching the receive-path convention (``process(_:into:)``'s server-emitted-
    /// reset charge). Unlike that path, this call is not wrapped by ``receive(_:)``'s GOAWAY-queuing
    /// catch (it is driven directly by the response side, not by feeding inbound octets), so on budget
    /// overflow this queues the GOAWAY itself before rethrowing — the caller only needs to flush
    /// whatever ``outboundBytes()`` now holds and close.
    public mutating func abortResponse(
        to streamID: HTTP2StreamID,
        code: HTTP2ErrorCode = .internalError
    ) throws(HTTP2Error) {
        guard streams.removeValue(forKey: streamID) != nil else {
            return
        }
        writer.writeRstStream(streamID, code: code)
        markStreamClosed(streamID, reason: .reset)
        do {
            try chargeStreamReset()
        }
        catch {
            if error.isConnectionError {
                writer.writeGoAway(lastStreamID: lastPeerStreamID, code: error.code)
            }
            throw error
        }
    }

    /// Encodes the response field section as an HPACK header block, `:status` first (RFC 9113 §8.3.2).
    ///
    /// Writes straight into a reserved buffer — no intermediate `[HPACKField]` array, no buffer
    /// regrowth, no per-response status itoa. Names use the canonical (lower-cased) form: HTTP/2 field
    /// names MUST be lowercase (§8.2.1), it is stored (so no per-field `rawName` materialization), and it
    /// is the same spelling for the registered names a response uses. Internal so an allocation test can
    /// measure it.
    mutating func encodeResponseSection(_ response: HTTPResponse) -> [UInt8] {
        var output: [UInt8] = []
        output.reserveCapacity(512)
        encoder.encode(
            HPACKField(name: ":status", value: response.status.decimalString), into: &output
        )
        for field in response.headerFields {
            encoder.encode(
                HPACKField(name: field.name.canonicalName, value: field.value), into: &output
            )
        }
        return output
    }
}
