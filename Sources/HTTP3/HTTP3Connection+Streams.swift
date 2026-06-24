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
        guard var state = streams[streamID] else { return }
        let decoded: (type: UInt64, consumed: Int)? = state.buffer.withUnsafeBytes { raw in
            var reader = ByteReader(raw)
            guard let type = QUICVarint.decode(&reader) else { return nil }
            return (type, reader.position)
        }
        guard let decoded else { return }  // the Stream Type varint has not fully arrived yet
        state.buffer.removeFirst(decoded.consumed)
        try assignUniStreamRole(
            streamID, role: HTTP3StreamRole(streamType: decoded.type), state: &state)
        streams[streamID] = state
        try dispatch(streamID, into: &events)  // process the remainder under the now-known kind
    }

    /// Assigns a unidirectional stream's role, enforcing the critical-stream singletons (§6.2.1) and
    /// refusing a client-initiated push stream (§6.2.2).
    private mutating func assignUniStreamRole(
        _ streamID: QUICStreamID,
        role: HTTP3StreamRole,
        state: inout StreamState
    ) throws(HTTP3Error) {
        switch role {
            case .control:
                guard peerControlStream == nil else {
                    throw .connection(.h3StreamCreationError, "a second control stream")
                }
                peerControlStream = streamID
                state.kind = .control
            case .qpackEncoder:
                guard peerQpackEncoderStream == nil else {
                    throw .connection(.h3StreamCreationError, "a second QPACK encoder stream")
                }
                peerQpackEncoderStream = streamID
                state.kind = .qpackEncoder
            case .qpackDecoder:
                guard peerQpackDecoderStream == nil else {
                    throw .connection(.h3StreamCreationError, "a second QPACK decoder stream")
                }
                peerQpackDecoderStream = streamID
                state.kind = .qpackDecoder
            case .push:
                throw .connection(.h3StreamCreationError, "a server must not receive a push stream")
            case .request, .reserved:
                state.kind = .reserved  // unknown / reserved types are tolerated; data discarded
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
        for frame in try drainFrames(streamID) {
            try handleControlFrame(frame, into: &events)
        }
        if streams[streamID]?.finReceived == true {
            throw .connection(.h3ClosedCriticalStream, "the control stream was closed")
        }
    }

    /// Validates and applies one control-stream frame (RFC 9114 §6.2.1 / §7.2).
    private mutating func handleControlFrame(
        _ frame: HTTP3FrameDecoder.Frame,
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
        _ payload: [UInt8], into events: inout [Event]
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
    private func handleCancelPush(_ payload: [UInt8]) throws(HTTP3Error) {
        guard let pushID = singleVarint(payload) else {
            throw .connection(.h3FrameError, "malformed CANCEL_PUSH")
        }
        guard pushID < (maxPushID ?? 0) else {
            throw .connection(.h3IdError, "CANCEL_PUSH for a push id above MAX_PUSH_ID")
        }
    }

    /// RFC 9114 §7.2.7 — a MAX_PUSH_ID must not decrease.
    private mutating func handleMaxPushID(_ payload: [UInt8]) throws(HTTP3Error) {
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
    mutating func processQpackEncoderStream(_ streamID: QUICStreamID) throws(HTTP3Error) {
        try parseQpackStream(streamID, isEncoder: true)
        if streams[streamID]?.finReceived == true {
            throw .connection(.h3ClosedCriticalStream, "the QPACK encoder stream was closed")
        }
    }

    /// Scans the peer's QPACK decoder stream for violations; its closure is a critical-stream error.
    mutating func processQpackDecoderStream(_ streamID: QUICStreamID) throws(HTTP3Error) {
        try parseQpackStream(streamID, isEncoder: false)
        if streams[streamID]?.finReceived == true {
            throw .connection(.h3ClosedCriticalStream, "the QPACK decoder stream was closed")
        }
    }

    /// Drains complete QPACK instructions, mapping a violation to its RFC 9204 §6 connection error.
    private mutating func parseQpackStream(
        _ streamID: QUICStreamID, isEncoder: Bool
    ) throws(HTTP3Error) {
        guard var state = streams[streamID] else { return }
        let maxCapacity = localSettings.qpackMaxTableCapacity
        let result: Result<Int, QPACKError> = state.buffer.withUnsafeBytes { raw in
            Result { () throws(QPACKError) in
                var reader = ByteReader(raw)
                if isEncoder {
                    try QPACKInstructions.parseEncoderStream(&reader, maxCapacity: maxCapacity)
                }
                else {
                    try QPACKInstructions.parseDecoderStream(&reader)
                }
                return reader.position
            }
        }
        switch result {
            case .success(let consumed):
                state.buffer.removeFirst(consumed)
                streams[streamID] = state
            case .failure(let error):
                throw .connection(qpack: error.code, error.reason)
        }
    }

    // MARK: Helpers

    /// Drains complete frames from a stream's buffer, advancing past the consumed octets.
    mutating func drainFrames(
        _ streamID: QUICStreamID
    ) throws(HTTP3Error) -> [HTTP3FrameDecoder.Frame] {
        guard var state = streams[streamID] else { return [] }
        let result: Result<(frames: [HTTP3FrameDecoder.Frame], consumed: Int), HTTP3Error> =
            state.buffer.withUnsafeBytes { raw in
                Result { () throws(HTTP3Error) in
                    var reader = ByteReader(raw)
                    var frames = [HTTP3FrameDecoder.Frame]()
                    while let frame = try frameDecoder.nextFrame(&reader) { frames.append(frame) }
                    return (frames, reader.position)
                }
            }
        switch result {
            case .success(let value):
                state.buffer.removeFirst(value.consumed)
                streams[streamID] = state
                return value.frames
            case .failure(let error):
                throw error
        }
    }

    /// Decodes exactly one varint that must occupy the whole payload, else nil (malformed).
    private func singleVarint(_ payload: [UInt8]) -> UInt64? {
        payload.withUnsafeBytes { raw in
            var reader = ByteReader(raw)
            guard let value = QUICVarint.decode(&reader), reader.isAtEnd else { return nil }
            return value
        }
    }

    /// Applies a received SETTINGS payload to ``remoteSettings`` (RFC 9114 §7.2.4).
    private mutating func applyPeerSettings(_ payload: [UInt8]) throws(HTTP3Error) {
        let result: Result<HTTP3Settings, HTTP3Error> = payload.withUnsafeBytes { raw in
            Result { () throws(HTTP3Error) in
                var settings = HTTP3Settings()
                try settings.apply(raw.bytes)
                return settings
            }
        }
        remoteSettings = try result.get()
    }
}
