//
//  HTTP2Connection+FlowControl.swift
//  HTTP2
//
//  RFC 9113 §6.9 — the connection's flow-control half: inbound DATA accounting (debiting the
//  connection and per-stream receive windows, replenishing each with a WINDOW_UPDATE at the
//  half-window), the inbound WINDOW_UPDATE that opens the send windows, the INITIAL_WINDOW_SIZE
//  shift, and the send-side flusher that releases queued response DATA as those windows allow.
//  Kept beside HTTP2Connection.swift so the core file stays focused on the receive pump.
//

internal import HTTPCore

extension HTTP2Connection {
    mutating func receiveData(
        _ frame: HTTP2FrameDecoder.Frame,
        into events: inout [Event]
    ) throws(HTTP2Error) {
        let streamID = frame.header.streamID
        // `removeValue` (not a subscript read) hands sole ownership of the record's body buffer to
        // `record`, so the append below mutates it in place. A subscript read would leave the dict
        // sharing the buffer, making every DATA frame copy the whole accumulated body — O(n²) over a
        // streamed upload. On any throw the record is simply dropped (the connection is closing).
        guard var record = streams.removeValue(forKey: streamID) else {
            // DATA on a recently-closed stream is a STREAM_CLOSED stream error (§5.1); on a
            // never-opened (idle) stream it is a connection PROTOCOL_ERROR (audit F1).
            if isRecentlyClosed(streamID) {
                throw .stream(streamID, .streamClosed, "DATA on a closed stream")
            }
            throw .connection(.protocolError, "DATA on an unopened stream")
        }
        // The entire DATA payload (incl. any padding) is flow-controlled (RFC 9113 §6.9.1).
        let length = frame.payload.count
        guard length <= connectionReceiveWindow else {
            throw .connection(.flowControlError, "DATA exceeded the connection receive window")
        }
        guard length <= record.receiveWindow else {
            throw .stream(streamID, .flowControlError, "DATA exceeded the stream receive window")
        }
        // CVE-2019-9518: a zero-length DATA frame that does not end the stream consumes no flow-control
        // window and carries no body — charge the cheap-frame budget so a flood trips ENHANCE_YOUR_CALM.
        if length == 0, !frame.header.flags.contains(.endStream) {
            try chargeControlFrame()
        }
        let body = try Self.dataBody(frame)
        let endStream = frame.header.flags.contains(.endStream)
        try record.stream.receiveData(endStream: endStream)
        // A tunnel stream's DATA is opaque (RFC 8441 §5): surface it as tunnel bytes — still
        // flow-controlled, but never buffered as a request body or bounded by the body limit.
        if record.isTunnel {
            consumeReceiveWindows(streamID, &record, by: length, endStream: endStream)
            streams[streamID] = record
            if !body.isEmpty { events.append(.tunnelData(streamID: streamID, bytes: Array(body))) }
            if endStream { events.append(.tunnelClosed(streamID: streamID)) }
            return
        }
        guard record.body.count + body.count <= limits.maxBodySize else {
            throw .stream(streamID, .enhanceYourCalm, "request body exceeds the limit")
        }
        record.body.append(contentsOf: body)
        consumeReceiveWindows(streamID, &record, by: length, endStream: endStream)
        streams[streamID] = record
        if endStream {
            try emitRequest(streamID, into: &events)
        }
    }

    /// The body octets of a DATA frame, stripping the PADDED pad-length and trailing padding.
    ///
    /// A pad length that is not strictly less than the payload is a PROTOCOL_ERROR (RFC 9113 §6.1).
    static func dataBody(_ frame: HTTP2FrameDecoder.Frame) throws(HTTP2Error) -> ArraySlice<UInt8> {
        guard frame.header.flags.contains(.padded) else {
            return frame.payload[...]
        }
        guard let padLength = frame.payload.first, Int(padLength) < frame.payload.count else {
            throw .connection(.protocolError, "DATA pad length exceeds the payload")
        }
        return frame.payload[1 ..< (frame.payload.count - Int(padLength))]
    }

    /// Debits the connection and stream receive windows by `length`, replenishing each with a
    /// WINDOW_UPDATE once half its window has been consumed so a large upload keeps flowing (§6.9).
    ///
    /// Batching at the half-window bounds the number of WINDOW_UPDATE frames. The stream window is not
    /// replenished after END_STREAM — no further DATA can arrive on it.
    mutating func consumeReceiveWindows(
        _ streamID: HTTP2StreamID,
        _ record: inout StreamRecord,
        by length: Int,
        endStream: Bool
    ) {
        connectionReceiveWindow -= length
        connectionReceiveConsumed += length
        if connectionReceiveConsumed * 2 >= 65_535 {
            writer.writeWindowUpdate(.connection, increment: connectionReceiveConsumed)
            connectionReceiveWindow += connectionReceiveConsumed
            connectionReceiveConsumed = 0
        }
        record.receiveWindow -= length
        record.receiveConsumed += length
        if !endStream, record.receiveConsumed * 2 >= localSettings.initialWindowSize {
            writer.writeWindowUpdate(streamID, increment: record.receiveConsumed)
            record.receiveWindow += record.receiveConsumed
            record.receiveConsumed = 0
        }
    }

    /// Releases as much pending response body as the send windows allow, in frame-sized chunks.
    ///
    /// Sends `record`'s queued body in `SETTINGS_MAX_FRAME_SIZE` chunks while the connection and
    /// stream send windows have room (RFC 9113 §6.9); the remainder stays queued for a later
    /// WINDOW_UPDATE. Each chunk's payload is appended as a slice — no per-frame intermediate `Array`.
    /// The stream is dropped only once fully flushed and closed; otherwise it is written back so its
    /// pending tail and windows survive.
    mutating func flushStream(_ streamID: HTTP2StreamID, _ record: inout StreamRecord) {
        let maxFrame = max(1, remoteSettings.maxFrameSize)
        while record.pendingOffset < record.pending.count {
            let room = min(connectionSendWindow.available, record.sendWindow.available)
            guard room > 0 else { break }  // windows exhausted — wait for a WINDOW_UPDATE
            let chunk = min(room, maxFrame, record.pending.count - record.pendingOffset)
            let end = record.pendingOffset + chunk
            let isLast = end == record.pending.count
            writer.writeData(
                streamID: streamID,
                endStream: isLast && record.pendingEndStream,
                record.pending[record.pendingOffset ..< end]
            )
            record.pendingOffset = end
            _ = connectionSendWindow.reserve(chunk)
            _ = record.sendWindow.reserve(chunk)
        }
        let fullyFlushed = record.pendingOffset >= record.pending.count
        guard !(fullyFlushed && record.stream.state == .closed) else {
            streams[streamID] = nil
            // Closed cleanly via END_STREAM: a late DATA is a survivable STREAM_CLOSED (audit F1), but a
            // HEADERS reusing this id is a connection error — the id cannot reopen (RFC 9113 §5.1).
            markStreamClosed(streamID, reason: .endStream)
            return
        }
        // Drop the octets already sent so a long-lived tunnel's queue stays bounded (RFC 8441 §5); a
        // one-shot response simply flushes to empty here.
        if record.pendingOffset > 0 {
            record.pending.removeFirst(record.pendingOffset)
            record.pendingOffset = 0
        }
        streams[streamID] = record
    }

    /// Flushes every stream that still has pending DATA — the connection send window just grew.
    mutating func flushAll() {
        for streamID in Array(streams.keys) {
            guard var record = streams.removeValue(forKey: streamID) else { continue }
            flushStream(streamID, &record)
        }
    }

    /// Applies a received WINDOW_UPDATE, replenishing the connection or a stream's send window and
    /// flushing any DATA that was waiting on it (RFC 9113 §6.9).
    mutating func receiveWindowUpdate(_ frame: HTTP2FrameDecoder.Frame) throws(HTTP2Error) {
        guard frame.payload.count == 4 else {
            throw .connection(.frameSizeError, "WINDOW_UPDATE payload must be 4 octets")
        }
        // The high bit is reserved; the increment is the low 31 bits (RFC 9113 §6.9.1).
        let increment = Int(
            frame.payload.withUnsafeBytes { UInt32(bigEndian: $0.loadUnaligned(as: UInt32.self)) }
                & 0x7FFF_FFFF
        )
        guard frame.header.streamID != .connection else {
            switch connectionSendWindow.increase(by: increment) {
                case .applied:
                    flushAll()
                case .zeroIncrement:
                    throw .connection(.protocolError, "WINDOW_UPDATE increment must be non-zero")
                case .overflow:
                    throw .connection(.flowControlError, "connection send window exceeded 2^31-1")
            }
            return
        }
        // A WINDOW_UPDATE for an idle stream (never opened) is a connection PROTOCOL_ERROR (RFC 9113
        // §5.1); for a stream the server has already closed and dropped it is ignored (§6.9).
        guard var record = streams.removeValue(forKey: frame.header.streamID) else {
            guard frame.header.streamID <= lastPeerStreamID else {
                throw .connection(.protocolError, "WINDOW_UPDATE on an idle stream")
            }
            // A WINDOW_UPDATE on an already-closed stream is ignored (§6.9) — but charge it: a flood is
            // cheap to send and otherwise unbudgeted.
            try chargeControlFrame()
            return
        }
        switch record.sendWindow.increase(by: increment) {
            case .applied:
                flushStream(frame.header.streamID, &record)
            case .zeroIncrement:
                streams[frame.header.streamID] = record
                throw .stream(
                    frame.header.streamID,
                    .protocolError,
                    "WINDOW_UPDATE increment must be non-zero"
                )
            case .overflow:
                streams[frame.header.streamID] = record
                throw .stream(
                    frame.header.streamID,
                    .flowControlError,
                    "stream send window exceeded 2^31-1"
                )
        }
    }

    /// Shifts every open stream's send window by `delta` after SETTINGS_INITIAL_WINDOW_SIZE changes
    /// (RFC 9113 §6.9.2), flushing any DATA a positive shift unblocks.
    mutating func shiftStreamSendWindows(by delta: Int) throws(HTTP2Error) {
        for streamID in Array(streams.keys) {
            guard var record = streams.removeValue(forKey: streamID) else { continue }
            switch record.sendWindow.shiftInitial(by: delta) {
                case .applied, .zeroIncrement:
                    flushStream(streamID, &record)
                case .overflow:
                    streams[streamID] = record
                    throw .connection(.flowControlError, "stream send window exceeded 2^31-1")
            }
        }
    }
}
