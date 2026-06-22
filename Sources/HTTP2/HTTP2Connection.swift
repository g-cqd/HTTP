//
//  HTTP2Connection.swift
//  HTTP2
//
//  RFC 9113 — the sans-I/O server connection engine. It is a pure state machine: `receive` is fed
//  inbound octets and returns high-level events (a complete request), while queued outbound octets
//  (the server preface, SETTINGS ACKs, PING ACKs, and responses) are drained with `outboundBytes`.
//  No sockets, no concurrency — the transport driver owns one instance per connection and pumps it.
//
//  Flow: the server queues its SETTINGS immediately (§3.4); the client preface (§3.4) is matched,
//  then its first SETTINGS frame is required (§6.5); thereafter frames are dispatched per type, with
//  HEADERS/CONTINUATION assembled (§6.10), HPACK-decoded (§4.3), mapped to an HTTPRequest (§8.3), and
//  the stream advanced through its state machine (§5.1).
//

internal import HPACK
public import HTTPCore

/// A sans-I/O HTTP/2 server connection (RFC 9113): feed it octets, drain octets, collect events.
public struct HTTP2Connection {

    /// A high-level event surfaced to the connection driver.
    public enum Event: Sendable, Equatable {

        /// A complete request arrived on a stream (all HEADERS and body received).
        case request(streamID: HTTP2StreamID, request: HTTPRequest, body: [UInt8])

        /// The peer reset a stream with the given code (RFC 9113 §6.4).
        case streamReset(streamID: HTTP2StreamID, code: HTTP2ErrorCode)
    }

    private enum Phase: Equatable {
        case awaitingPreface
        case awaitingSettings
        case active
    }

    private struct StreamRecord {
        var stream: HTTP2Stream
        var request: HTTPRequest
        var body: [UInt8]
    }

    private var phase = Phase.awaitingPreface
    private var inbound = [UInt8]()
    private var output = [UInt8]()
    private var decoder: HPACKDecoder
    private var encoder: HPACKEncoder
    private var accumulator: HTTP2HeaderBlockAccumulator
    private var streams: [HTTP2StreamID: StreamRecord] = [:]
    private var pendingHeadersEndStream = false
    private var lastPeerStreamID = HTTP2StreamID(0)
    private var activeStreamResets = 0
    private var remoteSettings = HTTP2Settings()
    private let frameDecoder: HTTP2FrameDecoder
    private let localSettings: HTTP2Settings
    private let limits: HTTPLimits

    /// Creates a connection that advertises `localSettings`, queuing the server SETTINGS preface (§3.4).
    public init(localSettings: HTTP2Settings = HTTP2Settings(), limits: HTTPLimits = .default) {
        self.localSettings = localSettings
        self.limits = limits
        self.decoder = HPACKDecoder(
            maxDynamicTableSize: localSettings.headerTableSize, limits: limits)
        self.encoder = HPACKEncoder(maxDynamicTableSize: remoteSettings.headerTableSize)
        self.accumulator = HTTP2HeaderBlockAccumulator(
            maxContinuationFrames: limits.maxContinuationFrames,
            maxBlockSize: limits.maxHeaderListSize)
        self.frameDecoder = HTTP2FrameDecoder(maxFrameSize: localSettings.maxFrameSize)
        writeFrame(.settings, payload: localSettings.encodePayload())
    }

    /// Drains the queued outbound octets (the server preface, ACKs, and responses).
    public mutating func outboundBytes() -> [UInt8] {
        defer { output.removeAll(keepingCapacity: true) }
        return output
    }

    /// Feeds inbound octets and returns any events they complete (RFC 9113).
    ///
    /// Throws an ``HTTP2Error`` with connection scope on a fatal protocol violation; the driver then
    /// sends GOAWAY (already queued) and closes.
    public mutating func receive(_ bytes: some Collection<UInt8>) throws(HTTP2Error) -> [Event] {
        inbound.append(contentsOf: bytes)
        if phase == .awaitingPreface {
            guard try consumePreface() else { return [] }
        }
        var events = [Event]()
        for frame in try drainFrames() {
            try process(frame, into: &events)
        }
        return events
    }

    // MARK: Preface

    private mutating func consumePreface() throws(HTTP2Error) -> Bool {
        let result: Result<Bool, HTTP2Error> = inbound.withUnsafeBytes { raw in
            Result { () throws(HTTP2Error) in
                var reader = ByteReader(raw)
                return try HTTP2ConnectionPreface.consume(&reader) == .matched
            }
        }
        guard try result.get() else { return false }
        inbound.removeFirst(HTTP2ConnectionPreface.client.count)
        phase = .awaitingSettings
        return true
    }

    // MARK: Frame decoding

    private mutating func drainFrames() throws(HTTP2Error) -> [HTTP2FrameDecoder.Frame] {
        let decoded: Result<(frames: [HTTP2FrameDecoder.Frame], consumed: Int), HTTP2Error> =
            inbound.withUnsafeBytes { raw in
                Result { () throws(HTTP2Error) in
                    var reader = ByteReader(raw)
                    var frames = [HTTP2FrameDecoder.Frame]()
                    while let frame = try frameDecoder.nextFrame(&reader) { frames.append(frame) }
                    return (frames, reader.position)
                }
            }
        switch decoded {
        case .success(let value):
            inbound.removeFirst(value.consumed)
            return value.frames
        case .failure(let error):
            throw error
        }
    }

    // MARK: Frame dispatch

    private mutating func process(
        _ frame: HTTP2FrameDecoder.Frame,
        into events: inout [Event]
    ) throws(HTTP2Error) {
        if phase == .awaitingSettings {
            guard frame.header.type == .settings else {
                throw .connection(.protocolError, "first frame after preface must be SETTINGS")
            }
            try applySettings(frame)
            phase = .active
            return
        }
        // While a header block is open, only CONTINUATION on that stream may arrive (§6.10).
        if accumulator.isExpectingContinuation, frame.header.type != .continuation {
            throw .connection(.protocolError, "expected CONTINUATION")
        }
        try dispatch(frame, into: &events)
    }

    private mutating func dispatch(
        _ frame: HTTP2FrameDecoder.Frame,
        into events: inout [Event]
    ) throws(HTTP2Error) {
        switch frame.header.type {
        case .headers: try receiveHeaders(frame, into: &events)
        case .continuation: try receiveContinuation(frame, into: &events)
        case .data: try receiveData(frame, into: &events)
        case .settings: try applySettings(frame)
        case .ping: receivePing(frame)
        case .rstStream: try receiveReset(frame, into: &events)
        case .windowUpdate, .priority, .goAway: break  // not yet acted on (no-op is safe here)
        default: break  // unknown frame types MUST be ignored (RFC 9113 §4.1)
        }
    }

    // MARK: SETTINGS / PING

    private mutating func applySettings(_ frame: HTTP2FrameDecoder.Frame) throws(HTTP2Error) {
        guard frame.header.streamID == .connection else {
            throw .connection(.protocolError, "SETTINGS must be on stream 0")
        }
        if frame.header.flags.contains(.ack) {
            guard frame.payload.isEmpty else {
                throw .connection(.frameSizeError, "SETTINGS ACK must be empty")
            }
            return  // acknowledgement of our settings; nothing to apply
        }
        var updated = remoteSettings  // SETTINGS frames are deltas applied to the running set
        let applied: Result<HTTP2Settings, HTTP2Error> = frame.payload.withUnsafeBytes { raw in
            Result { () throws(HTTP2Error) in
                try updated.apply(raw.bytes)
                return updated
            }
        }
        remoteSettings = try applied.get()
        writeFrame(.settings, flags: .ack)  // acknowledge (§6.5.3)
    }

    private mutating func receivePing(_ frame: HTTP2FrameDecoder.Frame) {
        guard !frame.header.flags.contains(.ack), frame.payload.count == 8 else { return }
        writeFrame(.ping, flags: .ack, streamID: .connection, payload: frame.payload)
    }

    // MARK: HEADERS / CONTINUATION / DATA

    private mutating func receiveHeaders(
        _ frame: HTTP2FrameDecoder.Frame,
        into events: inout [Event]
    ) throws(HTTP2Error) {
        let fragment = try HTTP2HeadersFrame.fieldBlockFragment(
            frame.payload, flags: frame.header.flags)
        pendingHeadersEndStream = frame.header.flags.contains(.endStream)
        let outcome = try accumulator.begin(
            streamID: frame.header.streamID, fragment: fragment,
            endHeaders: frame.header.flags.contains(.endHeaders))
        if case .complete(let streamID, let block) = outcome {
            try completeHeaderBlock(streamID, block: block, into: &events)
        }
    }

    private mutating func receiveContinuation(
        _ frame: HTTP2FrameDecoder.Frame,
        into events: inout [Event]
    ) throws(HTTP2Error) {
        let outcome = try accumulator.append(
            streamID: frame.header.streamID, fragment: frame.payload,
            endHeaders: frame.header.flags.contains(.endHeaders))
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
        guard streamID.isClientInitiated else {
            throw .connection(.protocolError, "client used a non-odd stream identifier")
        }
        guard streamID > lastPeerStreamID else {
            throw .connection(.protocolError, "stream identifier did not increase")
        }
        lastPeerStreamID = streamID

        let fields = try decodeHeaderBlock(block)
        let request = try HTTP2RequestMapper.makeRequest(from: fields, streamID: streamID)
        var stream = HTTP2Stream(id: streamID)
        try stream.receiveHeaders(endStream: endStream)
        streams[streamID] = StreamRecord(stream: stream, request: request, body: [])
        if endStream {
            emitRequest(streamID, into: &events)
        }
    }

    private mutating func receiveData(
        _ frame: HTTP2FrameDecoder.Frame,
        into events: inout [Event]
    ) throws(HTTP2Error) {
        guard var record = streams[frame.header.streamID] else {
            throw .connection(.protocolError, "DATA on an unopened stream")
        }
        let endStream = frame.header.flags.contains(.endStream)
        try record.stream.receiveData(endStream: endStream)
        guard record.body.count + frame.payload.count <= limits.maxBodySize else {
            throw .stream(frame.header.streamID, .enhanceYourCalm, "request body exceeds the limit")
        }
        record.body.append(contentsOf: frame.payload)
        streams[frame.header.streamID] = record
        if endStream {
            emitRequest(frame.header.streamID, into: &events)
        }
    }

    private mutating func receiveReset(
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
            activeStreamResets += 1
            guard activeStreamResets <= limits.maxStreamResetsPerInterval else {
                throw .connection(.enhanceYourCalm, "excessive stream resets (Rapid Reset)")
            }
        }
        let code =
            UInt32(frame.payload[0]) << 24 | UInt32(frame.payload[1]) << 16
            | UInt32(frame.payload[2]) << 8 | UInt32(frame.payload[3])
        streams[frame.header.streamID] = nil
        events.append(
            .streamReset(streamID: frame.header.streamID, code: HTTP2ErrorCode(code: code)))
    }

    // MARK: Response

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
        guard var record = streams[streamID] else {
            throw .connection(.internalError, "response for an unknown stream")
        }
        let hasBody = !body.isEmpty
        // Advance the state machine before touching the encoder, so a bad state never desyncs HPACK.
        try record.stream.sendHeaders(endStream: !hasBody)
        let block = encoder.encode(responseFields(response))
        var headerFlags: HTTP2FrameFlags = [.endHeaders]
        if !hasBody { headerFlags.insert(.endStream) }
        writeFrame(.headers, flags: headerFlags, streamID: streamID, payload: block)
        if hasBody {
            try record.stream.sendData(endStream: true)
            writeData(streamID: streamID, body: body)
        }
        streams[streamID] = record.stream.state == .closed ? nil : record
    }

    private func responseFields(_ response: HTTPResponse) -> [HPACKField] {
        var fields = [HPACKField(name: ":status", value: String(response.status.code))]
        for field in response.headerFields {
            fields.append(HPACKField(name: field.name.rawName, value: field.value))
        }
        return fields
    }

    private mutating func writeData(streamID: HTTP2StreamID, body: [UInt8]) {
        let maxChunk = max(1, remoteSettings.maxFrameSize)
        var offset = 0
        while offset < body.count {
            let end = min(offset + maxChunk, body.count)
            writeFrame(
                .data, flags: end == body.count ? [.endStream] : [], streamID: streamID,
                payload: Array(body[offset..<end]))
            offset = end
        }
    }

    // MARK: Helpers

    private mutating func emitRequest(_ streamID: HTTP2StreamID, into events: inout [Event]) {
        guard let record = streams[streamID] else { return }
        events.append(.request(streamID: streamID, request: record.request, body: record.body))
    }

    private mutating func decodeHeaderBlock(_ block: [UInt8]) throws(HTTP2Error) -> [HPACKField] {
        let decoded: Result<[HPACKField], HPACKError> = block.withUnsafeBytes { raw in
            Result { () throws(HPACKError) in try decoder.decode(raw.bytes) }
        }
        switch decoded {
        case .success(let fields): return fields
        case .failure: throw .connection(.compressionError, "HPACK decoding failed")
        }
    }

    private mutating func writeFrame(
        _ type: HTTP2FrameType,
        flags: HTTP2FrameFlags = [],
        streamID: HTTP2StreamID = .connection,
        payload: [UInt8] = []
    ) {
        let header = HTTP2FrameHeader(
            payloadLength: payload.count, type: type, flags: flags, streamID: streamID)
        header.encode(into: &output)
        output.append(contentsOf: payload)
    }
}
