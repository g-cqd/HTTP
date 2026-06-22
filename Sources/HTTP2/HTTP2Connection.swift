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

    struct StreamRecord {
        var stream: HTTP2Stream
        var request: HTTPRequest
        var body: [UInt8]
        /// The stream's send window — DATA octets the peer will accept on this stream (RFC 9113
        /// §6.9.2), seeded from the peer's `SETTINGS_INITIAL_WINDOW_SIZE`.
        var sendWindow: HTTP2FlowControlWindow
        /// The stream's receive window — DATA octets we will still accept on this stream before the
        /// peer must wait for a WINDOW_UPDATE (RFC 9113 §6.9), seeded from the window we advertised.
        var receiveWindow: Int
        /// Octets received on this stream since we last replenished its window with a WINDOW_UPDATE.
        var receiveConsumed = 0
        /// Response body queued for sending, the offset already flushed, and whether the final frame
        /// carries END_STREAM.
        ///
        /// DATA past the send window waits here until a WINDOW_UPDATE opens it.
        var pending: [UInt8] = []
        var pendingOffset = 0
        var pendingEndStream = false
    }

    private var phase = Phase.awaitingPreface
    private var inbound = [UInt8]()
    var writer = HTTP2FrameWriter()
    private var decoder: HPACKDecoder
    var encoder: HPACKEncoder
    private var accumulator: HTTP2HeaderBlockAccumulator
    var streams: [HTTP2StreamID: StreamRecord] = [:]
    /// The connection-level send window — total DATA octets the peer will currently accept across all
    /// streams (RFC 9113 §6.9.1).
    ///
    /// Replenished by a stream-0 WINDOW_UPDATE.
    private var connectionSendWindow = HTTP2FlowControlWindow()
    /// The connection-level receive window — DATA octets we still accept across all streams before a
    /// replenishing stream-0 WINDOW_UPDATE (RFC 9113 §6.9.1).
    ///
    /// Its initial value is fixed at 65,535 by the protocol and is not changed by SETTINGS.
    private var connectionReceiveWindow = 65_535
    /// Octets received since we last replenished the connection window with a WINDOW_UPDATE.
    private var connectionReceiveConsumed = 0
    private var pendingHeadersEndStream = false
    private var lastPeerStreamID = HTTP2StreamID(0)
    private var activeStreamResets = 0
    /// Leaky-bucket budget for ACK-generating control frames (PING / SETTINGS).
    ///
    /// Each charges it and a completed request drains it; a flood with no useful work in between
    /// trips ENHANCE_YOUR_CALM (RFC 9113 §6.5 / §6.7).
    private var controlFrameBudget = 0
    private var remoteSettings = HTTP2Settings()
    private let frameDecoder: HTTP2FrameDecoder
    private let localSettings: HTTP2Settings
    private let limits: HTTPLimits
    /// The concurrent-stream cap advertised to and enforced against the peer (RFC 9113 §5.1.2).
    private let maxConcurrentStreams: Int

    /// Creates a connection that advertises `localSettings`, queuing the server SETTINGS preface (§3.4).
    public init(localSettings: HTTP2Settings = HTTP2Settings(), limits: HTTPLimits = .default) {
        // A server MUST NOT advertise ENABLE_PUSH with a non-zero value (RFC 9113 §6.5.2).
        var advertised = localSettings
        advertised.enablePush = false
        // Advertise + enforce a concurrent-stream cap (RFC 9113 §5.1.2); default to the limits knob.
        if advertised.maxConcurrentStreams == nil {
            advertised.maxConcurrentStreams = limits.maxConcurrentStreams
        }
        self.localSettings = advertised
        self.maxConcurrentStreams = advertised.maxConcurrentStreams ?? limits.maxConcurrentStreams
        self.limits = limits
        self.decoder = HPACKDecoder(
            maxDynamicTableSize: advertised.headerTableSize, limits: limits)
        self.encoder = HPACKEncoder(maxDynamicTableSize: remoteSettings.headerTableSize)
        self.accumulator = HTTP2HeaderBlockAccumulator(
            maxContinuationFrames: limits.maxContinuationFrames,
            maxBlockSize: limits.maxHeaderListSize)
        self.frameDecoder = HTTP2FrameDecoder(maxFrameSize: advertised.maxFrameSize)
        writer.writeFrame(.settings, payload: advertised.encodePayload())
    }

    /// Drains the queued outbound octets (the server preface, ACKs, and responses).
    public mutating func outboundBytes() -> [UInt8] {
        writer.drain()
    }

    /// Feeds inbound octets and returns any events they complete (RFC 9113).
    ///
    /// Throws an ``HTTP2Error`` with connection scope on a fatal protocol violation; the driver then
    /// sends GOAWAY (already queued) and closes.
    public mutating func receive(_ bytes: some Collection<UInt8>) throws(HTTP2Error) -> [Event] {
        do {
            inbound.append(contentsOf: bytes)
            if phase == .awaitingPreface {
                guard try consumePreface() else { return [] }
            }
            var events = [Event]()
            for frame in try drainFrames() {
                try process(frame, into: &events)
            }
            return events
        } catch {
            // A connection-scoped error is fatal: queue GOAWAY naming the last processed stream and
            // the cause (RFC 9113 §6.8) so the driver can flush it before closing.
            if error.isConnectionError {
                writer.writeGoAway(lastStreamID: lastPeerStreamID, code: error.code)
            }
            throw error
        }
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
        case .ping: try receivePing(frame)
        case .rstStream: try receiveReset(frame, into: &events)
        case .windowUpdate: try receiveWindowUpdate(frame)
        case .priority, .goAway: break  // not yet acted on (no-op is safe here)
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

    private mutating func receivePing(_ frame: HTTP2FrameDecoder.Frame) throws(HTTP2Error) {
        guard frame.header.streamID == .connection else {
            throw .connection(.protocolError, "PING must be on stream 0 (RFC 9113 §6.7)")
        }
        guard frame.payload.count == 8 else {
            throw .connection(.frameSizeError, "PING payload must be 8 octets (RFC 9113 §6.7)")
        }
        guard !frame.header.flags.contains(.ack) else { return }  // a PING ACK needs no response
        try chargeControlFrame()
        writer.writeFrame(.ping, flags: .ack, streamID: .connection, payload: frame.payload)
    }

    /// Charges one ACK-generating control frame against the flood budget, failing closed if a peer
    /// floods PING/SETTINGS without useful work in between (RFC 9113 §6.5 / §6.7).
    private mutating func chargeControlFrame() throws(HTTP2Error) {
        controlFrameBudget += 1
        guard controlFrameBudget <= limits.maxStreamResetsPerInterval else {
            throw .connection(.enhanceYourCalm, "excessive PING/SETTINGS frames")
        }
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
        // Refuse a stream past the concurrency cap (RFC 9113 §5.1.2). The block was still HPACK-
        // decoded above so the dynamic table stays in sync; RST_STREAM(REFUSED_STREAM) keeps the
        // connection alive instead of opening the stream.
        guard streams.count < maxConcurrentStreams else {
            writer.writeRstStream(streamID, code: .refusedStream)
            return
        }
        let request = try HTTP2RequestMapper.makeRequest(from: fields, streamID: streamID)
        var stream = HTTP2Stream(id: streamID)
        try stream.receiveHeaders(endStream: endStream)
        streams[streamID] = StreamRecord(
            stream: stream, request: request, body: [],
            sendWindow: HTTP2FlowControlWindow(initialSize: remoteSettings.initialWindowSize),
            receiveWindow: localSettings.initialWindowSize)
        if endStream {
            emitRequest(streamID, into: &events)
        }
    }

    private mutating func receiveData(
        _ frame: HTTP2FrameDecoder.Frame,
        into events: inout [Event]
    ) throws(HTTP2Error) {
        let streamID = frame.header.streamID
        // `removeValue` (not a subscript read) hands sole ownership of the record's body buffer to
        // `record`, so the append below mutates it in place. A subscript read would leave the dict
        // sharing the buffer, making every DATA frame copy the whole accumulated body — O(n²) over a
        // streamed upload. On any throw the record is simply dropped (the connection is closing).
        guard var record = streams.removeValue(forKey: streamID) else {
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
        let endStream = frame.header.flags.contains(.endStream)
        try record.stream.receiveData(endStream: endStream)
        guard record.body.count + length <= limits.maxBodySize else {
            throw .stream(streamID, .enhanceYourCalm, "request body exceeds the limit")
        }
        record.body.append(contentsOf: frame.payload)
        consumeReceiveWindows(streamID, &record, by: length, endStream: endStream)
        streams[streamID] = record
        if endStream {
            emitRequest(streamID, into: &events)
        }
    }

    /// Debits the connection and stream receive windows by `length`, replenishing each with a
    /// WINDOW_UPDATE once half its window has been consumed so a large upload keeps flowing (§6.9).
    ///
    /// Batching at the half-window bounds the number of WINDOW_UPDATE frames. The stream window is not
    /// replenished after END_STREAM — no further DATA can arrive on it.
    private mutating func consumeReceiveWindows(
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
        // The 4-octet error code is big-endian (RFC 9113 §6.4); read it as one unaligned load rather
        // than re-rolling the shift-and-or by hand (the payload is exactly 4 octets, guarded above).
        let code = frame.payload.withUnsafeBytes {
            UInt32(bigEndian: $0.loadUnaligned(as: UInt32.self))
        }
        streams[frame.header.streamID] = nil
        events.append(
            .streamReset(streamID: frame.header.streamID, code: HTTP2ErrorCode(code: code)))
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
                streamID: streamID, endStream: isLast && record.pendingEndStream,
                record.pending[record.pendingOffset..<end])
            record.pendingOffset = end
            _ = connectionSendWindow.reserve(chunk)
            _ = record.sendWindow.reserve(chunk)
        }
        let fullyFlushed = record.pendingOffset >= record.pending.count
        streams[streamID] = fullyFlushed && record.stream.state == .closed ? nil : record
    }

    /// Flushes every stream that still has pending DATA — the connection send window just grew.
    private mutating func flushAll() {
        for streamID in Array(streams.keys) {
            guard var record = streams.removeValue(forKey: streamID) else { continue }
            flushStream(streamID, &record)
        }
    }

    /// Applies a received WINDOW_UPDATE, replenishing the connection or a stream's send window and
    /// flushing any DATA that was waiting on it (RFC 9113 §6.9).
    private mutating func receiveWindowUpdate(_ frame: HTTP2FrameDecoder.Frame) throws(HTTP2Error) {
        guard frame.payload.count == 4 else {
            throw .connection(.frameSizeError, "WINDOW_UPDATE payload must be 4 octets")
        }
        // The high bit is reserved; the increment is the low 31 bits (RFC 9113 §6.9.1).
        let increment = Int(
            frame.payload.withUnsafeBytes { UInt32(bigEndian: $0.loadUnaligned(as: UInt32.self)) }
                & 0x7FFF_FFFF)
        guard frame.header.streamID != .connection else {
            switch connectionSendWindow.increase(by: increment) {
            case .applied: flushAll()
            case .zeroIncrement:
                throw .connection(.protocolError, "WINDOW_UPDATE increment must be non-zero")
            case .overflow:
                throw .connection(.flowControlError, "connection send window exceeded 2^31-1")
            }
            return
        }
        // A WINDOW_UPDATE may legitimately arrive for a stream the server has already closed and
        // dropped (RFC 9113 §6.9); ignore it rather than treating it as a protocol error.
        guard var record = streams.removeValue(forKey: frame.header.streamID) else { return }
        switch record.sendWindow.increase(by: increment) {
        case .applied:
            flushStream(frame.header.streamID, &record)
        case .zeroIncrement:
            streams[frame.header.streamID] = record
            throw .stream(
                frame.header.streamID, .protocolError, "WINDOW_UPDATE increment must be non-zero")
        case .overflow:
            streams[frame.header.streamID] = record
            throw .stream(
                frame.header.streamID, .flowControlError, "stream send window exceeded 2^31-1")
        }
    }

    /// Shifts every open stream's send window by `delta` after SETTINGS_INITIAL_WINDOW_SIZE changes
    /// (RFC 9113 §6.9.2), flushing any DATA a positive shift unblocks.
    private mutating func shiftStreamSendWindows(by delta: Int) throws(HTTP2Error) {
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

    // MARK: Helpers

    private mutating func emitRequest(_ streamID: HTTP2StreamID, into events: inout [Event]) {
        guard let record = streams[streamID] else { return }
        controlFrameBudget = max(0, controlFrameBudget - 1)  // useful work drains the flood budget
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
}
