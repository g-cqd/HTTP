//
//  HTTP2Connection+ControlFrames.swift
//  HTTP2
//
//  RFC 9113 — the connection-level control-frame handlers split out of the receive pump: SETTINGS
//  (§6.5) and PING (§6.7), each charged against the flood budget and acknowledged, plus the
//  validate-only PRIORITY (§6.3) and GOAWAY (§6.8) handlers and the RST_STREAM (§6.4) handler. Kept
//  beside HTTP2Connection.swift so the core file stays focused on the preface/decode/dispatch loop.
//

extension HTTP2Connection {
    /// Validates a PRIORITY frame (RFC 9113 §6.3); the deprecated priority data (§5.3.2) is not used.
    mutating func receivePriority(_ frame: HTTP2FrameDecoder.Frame) throws(HTTP2Error) {
        guard frame.header.streamID != .connection else {
            throw .connection(.protocolError, "PRIORITY must not be on stream 0")
        }
        guard frame.payload.count == 5 else {
            throw .stream(frame.header.streamID, .frameSizeError, "PRIORITY must be 5 octets")
        }
        let dependency = HTTP2StreamID(
            rawValue: frame.payload.withUnsafeBytes {
                UInt32(bigEndian: $0.loadUnaligned(as: UInt32.self))
            }
        )
        guard dependency != frame.header.streamID else {
            throw .stream(frame.header.streamID, .protocolError, "stream depends on itself")
        }
        // A well-formed PRIORITY does no useful work; charge it so a flood trips ENHANCE_YOUR_CALM
        // (CVE-2019-9513). A malformed one already failed above as a stream/connection error.
        try chargeControlFrame()
    }

    /// Validates a received GOAWAY (RFC 9113 §6.8); a client GOAWAY is informational to a server.
    func receiveGoAway(_ frame: HTTP2FrameDecoder.Frame) throws(HTTP2Error) {
        guard frame.header.streamID == .connection else {
            throw .connection(.protocolError, "GOAWAY must be on stream 0")
        }
    }

    // MARK: SETTINGS / PING

    mutating func applySettings(_ frame: HTTP2FrameDecoder.Frame) throws(HTTP2Error) {
        guard frame.header.streamID == .connection else {
            throw .connection(.protocolError, "SETTINGS must be on stream 0")
        }
        if frame.header.flags.contains(.ack) {
            guard frame.payload.isEmpty else {
                throw .connection(.frameSizeError, "SETTINGS ACK must be empty")
            }
            try chargeControlFrame()  // a SETTINGS-ACK flood is cheap to send — charge it
            return  // acknowledgement of our settings; nothing else to apply
        }
        try chargeControlFrame()
        let previousInitialWindow = remoteSettings.initialWindowSize
        var updated = remoteSettings  // SETTINGS frames are deltas applied to the running set
        let applied: Result<HTTP2Settings, HTTP2Error> = frame.payload.withUnsafeBytes { raw in
            Result { () throws(HTTP2Error) in
                try updated.apply(raw.bytes)
                return updated
            }
        }
        remoteSettings = try applied.get()
        // A change to SETTINGS_INITIAL_WINDOW_SIZE shifts every open stream's send window by the same
        // delta (RFC 9113 §6.9.2); a positive shift may unblock DATA that was waiting on the window.
        let windowDelta = remoteSettings.initialWindowSize - previousInitialWindow
        if windowDelta != 0 {
            try shiftStreamSendWindows(by: windowDelta)
        }
        writer.writeFrame(.settings, flags: .ack)  // acknowledge (§6.5.3)
    }

    mutating func receivePing(_ frame: HTTP2FrameDecoder.Frame) throws(HTTP2Error) {
        guard frame.header.streamID == .connection else {
            throw .connection(.protocolError, "PING must be on stream 0 (RFC 9113 §6.7)")
        }
        guard frame.payload.count == 8 else {
            throw .connection(.frameSizeError, "PING payload must be 8 octets (RFC 9113 §6.7)")
        }
        guard !frame.header.flags.contains(.ack) else {  // a PING ACK needs no response
            return
        }
        try chargeControlFrame()
        writer.writeFrame(.ping, flags: .ack, streamID: .connection, payload: frame.payload)
    }

    // MARK: RST_STREAM

    /// Handles a received RST_STREAM (RFC 9113 §6.4): closes the stream, charges the Rapid-Reset budget
    /// when it was still active, and surfaces the peer's error code as a `.streamReset` event.
    mutating func receiveReset(
        _ frame: HTTP2FrameDecoder.Frame,
        into events: inout [Event]
    ) throws(HTTP2Error) {
        guard frame.payload.count == 4 else {
            throw .connection(.frameSizeError, "RST_STREAM payload must be 4 octets")
        }
        guard frame.header.streamID != .connection, frame.header.streamID <= lastPeerStreamID else {
            throw .connection(.protocolError, "RST_STREAM on an idle or connection-level stream")
        }
        // Resetting a stream the server is still working on is the Rapid Reset signature
        // (CVE-2023-44487). A clock-free per-connection cap on such resets fails closed with
        // ENHANCE_YOUR_CALM before the cheap-to-send / costly-to-process churn does damage.
        if streams[frame.header.streamID] != nil {
            try chargeStreamReset()
        }
        // The 4-octet error code is big-endian (RFC 9113 §6.4); read it as one unaligned load rather
        // than re-rolling the shift-and-or by hand (the payload is exactly 4 octets, guarded above).
        let code = frame.payload.withUnsafeBytes {
            UInt32(bigEndian: $0.loadUnaligned(as: UInt32.self))
        }
        streams[frame.header.streamID] = nil
        markStreamClosed(frame.header.streamID, reason: .reset)
        events.append(
            .streamReset(streamID: frame.header.streamID, code: HTTP2ErrorCode(code: code))
        )
    }
}
