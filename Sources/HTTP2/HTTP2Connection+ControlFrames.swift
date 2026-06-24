//
//  HTTP2Connection+ControlFrames.swift
//  HTTP2
//
//  RFC 9113 — the connection-level control-frame handlers split out of the receive pump: SETTINGS
//  (§6.5) and PING (§6.7), each charged against the flood budget and acknowledged, plus the
//  validate-only PRIORITY (§6.3) and GOAWAY (§6.8) handlers. Kept beside HTTP2Connection.swift so the
//  core file stays focused on the preface/decode/dispatch loop.
//

extension HTTP2Connection {
    /// Validates a PRIORITY frame (RFC 9113 §6.3); the deprecated priority data (§5.3.2) is not used.
    func receivePriority(_ frame: HTTP2FrameDecoder.Frame) throws(HTTP2Error) {
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
            return  // acknowledgement of our settings; nothing to apply
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
}
