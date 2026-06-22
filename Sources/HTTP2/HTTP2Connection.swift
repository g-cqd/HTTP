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
public import HTTPConcurrency
public import HTTPCore

/// A sans-I/O HTTP/2 server connection (RFC 9113): feed it octets, drain octets, collect events.
public struct HTTP2Connection {

    /// A high-level event surfaced to the connection driver.
    public enum Event: Sendable, Equatable {

        /// A complete request arrived on a stream (all HEADERS and body received).
        case request(streamID: HTTP2StreamID, request: HTTPRequest, body: [UInt8])

        /// An Extended CONNECT opened a tunnel on a stream (RFC 8441 §4) — `protocol` names it (e.g.
        /// `"websocket"`, RFC 9220). The driver accepts with ``acceptTunnel(_:)`` or resets the stream.
        case extendedConnect(streamID: HTTP2StreamID, request: HTTPRequest, protocol: String)

        /// Opaque bytes arrived on a tunnel stream's DATA frames (RFC 8441 §5).
        case tunnelData(streamID: HTTP2StreamID, bytes: [UInt8])

        /// The peer ended a tunnel stream with END_STREAM (RFC 8441 §5).
        case tunnelClosed(streamID: HTTP2StreamID)

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
        /// Whether this stream is an Extended CONNECT tunnel (RFC 8441 §5): its DATA carries opaque
        /// tunnel bytes (e.g. WebSocket frames) rather than an HTTP request/response body.
        var isTunnel = false
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
    var connectionSendWindow = HTTP2FlowControlWindow()
    /// The connection-level receive window — DATA octets we still accept across all streams before a
    /// replenishing stream-0 WINDOW_UPDATE (RFC 9113 §6.9.1).
    ///
    /// Its initial value is fixed at 65,535 by the protocol and is not changed by SETTINGS.
    var connectionReceiveWindow = 65_535
    /// Octets received since we last replenished the connection window with a WINDOW_UPDATE.
    var connectionReceiveConsumed = 0
    private var pendingHeadersEndStream = false
    /// The deprecated priority-section stream dependency of the open HEADERS block, if any (RFC 9113
    /// §5.3.2) — captured when the HEADERS frame arrives, checked after the block decodes so a
    /// self-dependency is rejected as a stream error without desyncing the HPACK table (§5.3.1).
    private var pendingHeadersDependency: HTTP2StreamID?
    var lastPeerStreamID = HTTP2StreamID(0)
    private var activeStreamResets = 0
    /// Monotonic clock and rolling-window start for the abuse budgets (Rapid-Reset / MadeYouReset
    /// rate limiting, RFC 9113).
    ///
    /// The budgets reset every `resetIntervalNanos`, so a cap is a *rate* over `streamResetInterval`,
    /// not a per-connection total — closing both the long-window bypass and the false positive against
    /// a legitimately long-lived connection.
    private let now: MonotonicNowProvider
    private var windowStart: MonotonicNanoseconds
    private let resetIntervalNanos: MonotonicNanoseconds
    /// Leaky-bucket budget for ACK-generating control frames (PING / SETTINGS).
    ///
    /// Each charges it and a completed request drains it; a flood with no useful work in between
    /// trips ENHANCE_YOUR_CALM (RFC 9113 §6.5 / §6.7).
    private var controlFrameBudget = 0
    var remoteSettings = HTTP2Settings()
    private let frameDecoder: HTTP2FrameDecoder
    let localSettings: HTTP2Settings
    let limits: HTTPLimits
    /// The concurrent-stream cap advertised to and enforced against the peer (RFC 9113 §5.1.2).
    private let maxConcurrentStreams: Int

    /// Creates a connection that advertises `localSettings`, queuing the server SETTINGS preface (§3.4).
    ///
    /// `now` is the monotonic clock the Rapid-Reset / MadeYouReset rolling window is measured against;
    /// it defaults to the live clock and a test injects a controllable one.
    public init(
        localSettings: HTTP2Settings = HTTP2Settings(),
        limits: HTTPLimits = .default,
        now: @escaping MonotonicNowProvider = LiveMonotonicClock.now
    ) {
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
        self.now = now
        self.windowStart = now()
        self.resetIntervalNanos = limits.streamResetInterval.monotonicNanoseconds
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
        do {
            try dispatch(frame, into: &events)
        } catch {
            // A stream-scoped error resets just that stream and the connection continues (RFC 9113
            // §5.4.2); a connection-scoped error propagates to GOAWAY + close (§5.4.1).
            guard let streamID = error.streamID else { throw error }
            writer.writeRstStream(streamID, code: error.code)
            streams[streamID] = nil
            // A server-*emitted* RST_STREAM counts against the reset budget too — otherwise an attacker
            // provokes unbounded resets the client never sends, bypassing the Rapid-Reset defense:
            // MadeYouReset (CVE-2025-8671).
            try chargeStreamReset()
        }
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
        case .priority: try receivePriority(frame)
        case .goAway: try receiveGoAway(frame)
        case .pushPromise:
            throw .connection(.protocolError, "a client must not send PUSH_PROMISE (RFC 9113 §8.4)")
        default: break  // unknown frame types MUST be ignored (RFC 9113 §4.1)
        }
    }

    /// Validates a PRIORITY frame (RFC 9113 §6.3); the deprecated priority data (§5.3.2) is not used.
    private func receivePriority(_ frame: HTTP2FrameDecoder.Frame) throws(HTTP2Error) {
        guard frame.header.streamID != .connection else {
            throw .connection(.protocolError, "PRIORITY must not be on stream 0")
        }
        guard frame.payload.count == 5 else {
            throw .stream(frame.header.streamID, .frameSizeError, "PRIORITY must be 5 octets")
        }
        let dependency = HTTP2StreamID(
            rawValue: frame.payload.withUnsafeBytes {
                UInt32(bigEndian: $0.loadUnaligned(as: UInt32.self))
            })
        guard dependency != frame.header.streamID else {
            throw .stream(frame.header.streamID, .protocolError, "stream depends on itself")
        }
    }

    /// Validates a received GOAWAY (RFC 9113 §6.8); a client GOAWAY is informational to a server.
    private func receiveGoAway(_ frame: HTTP2FrameDecoder.Frame) throws(HTTP2Error) {
        guard frame.header.streamID == .connection else {
            throw .connection(.protocolError, "GOAWAY must be on stream 0")
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
        decayBudgetsIfElapsed()
        controlFrameBudget += 1
        guard controlFrameBudget <= limits.maxStreamResetsPerInterval else {
            throw .connection(.enhanceYourCalm, "excessive PING/SETTINGS frames")
        }
    }

    /// Resets the abuse budgets once the rolling window has elapsed, so each cap is a *rate* over
    /// `streamResetInterval` rather than a monotonic per-connection total (RFC 9113 Rapid-Reset
    /// defense) — fixing both the long-window bypass and the false positive on long-lived connections.
    private mutating func decayBudgetsIfElapsed() {
        let timestamp = now()
        guard timestamp - windowStart >= resetIntervalNanos else { return }
        windowStart = timestamp
        activeStreamResets = 0
        controlFrameBudget = 0
    }

    /// Charges one stream reset against the rolling budget — whether the peer sent RST_STREAM or the
    /// engine emitted one for a stream-scoped violation — tripping ENHANCE_YOUR_CALM past the cap
    /// (RFC 9113; Rapid Reset CVE-2023-44487 / MadeYouReset CVE-2025-8671).
    private mutating func chargeStreamReset() throws(HTTP2Error) {
        decayBudgetsIfElapsed()
        activeStreamResets += 1
        guard activeStreamResets <= limits.maxStreamResetsPerInterval else {
            throw .connection(
                .enhanceYourCalm, "excessive stream resets (Rapid Reset / MadeYouReset)")
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
        pendingHeadersDependency = HTTP2HeadersFrame.priorityDependency(
            frame.payload, flags: frame.header.flags)
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
        let fields = try decodeHeaderBlock(block)  // always decode, to keep the HPACK table in sync

        // A second HEADERS block on an already-open stream is trailers (RFC 9113 §8.1).
        if streams[streamID] != nil {
            try applyTrailers(streamID, endStream: endStream, into: &events)
            return
        }
        guard streamID.isClientInitiated else {
            throw .connection(.protocolError, "client used a non-odd stream identifier")
        }
        guard streamID > lastPeerStreamID else {
            throw .connection(.protocolError, "stream identifier did not increase")
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
            return
        }
        let (request, connectProtocol) = try HTTP2RequestMapper.makeRequest(
            from: fields, streamID: streamID)
        var stream = HTTP2Stream(id: streamID)
        try stream.receiveHeaders(endStream: endStream)
        var record = StreamRecord(
            stream: stream, request: request, body: [],
            sendWindow: HTTP2FlowControlWindow(initialSize: remoteSettings.initialWindowSize),
            receiveWindow: localSettings.initialWindowSize)
        // An Extended CONNECT (RFC 8441 §4) opens a tunnel rather than a request: surface it for the
        // driver to accept, and route this stream's DATA as opaque tunnel bytes from here on.
        if let connectProtocol {
            guard localSettings.enableConnectProtocol else {
                throw .stream(streamID, .protocolError, "Extended CONNECT was not enabled")
            }
            record.isTunnel = true
            streams[streamID] = record
            events.append(
                .extendedConnect(streamID: streamID, request: request, protocol: connectProtocol))
            return
        }
        streams[streamID] = record
        if endStream {
            try emitRequest(streamID, into: &events)
        }
    }

    /// Applies a trailing HEADERS block (trailers, RFC 9113 §8.1) — it must end the stream.
    private mutating func applyTrailers(
        _ streamID: HTTP2StreamID,
        endStream: Bool,
        into events: inout [Event]
    ) throws(HTTP2Error) {
        guard var record = streams.removeValue(forKey: streamID) else { return }
        do {
            try record.stream.receiveHeaders(endStream: endStream)  // trailers must set END_STREAM
        } catch {
            streams[streamID] = record
            throw error
        }
        streams[streamID] = record
        if endStream { try emitRequest(streamID, into: &events) }
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
            try chargeStreamReset()
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

    // MARK: Helpers

    mutating func emitRequest(
        _ streamID: HTTP2StreamID, into events: inout [Event]
    )
        throws(HTTP2Error)
    {
        guard let record = streams[streamID] else { return }
        try validateContentLength(record)
        controlFrameBudget = max(0, controlFrameBudget - 1)  // useful work drains the flood budget
        events.append(.request(streamID: streamID, request: record.request, body: record.body))
    }

    /// A declared `content-length` must match the body received; absent is fine, anything else is a
    /// malformed request (RFC 9113 §8.1.1) and a stream error.
    private func validateContentLength(_ record: StreamRecord) throws(HTTP2Error) {
        switch record.request.headerFields.contentLength {
        case .absent:
            return
        case .invalid:
            throw .stream(record.stream.id, .protocolError, "invalid content-length")
        case .length(let declared):
            guard declared == record.body.count else {
                throw .stream(
                    record.stream.id, .protocolError, "content-length does not match body")
            }
        }
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
