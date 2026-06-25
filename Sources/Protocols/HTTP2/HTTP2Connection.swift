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
        /// The stream's RFC 9218 §4 urgency (0 = most urgent … 7 = least; default 3), cached from the
        /// request's `Priority` field at creation so the send-side flusher can release a congested
        /// connection's higher-priority DATA first (see `flushAll`, HTTP2Connection+FlowControl).
        var urgency = HTTPPriority.defaultUrgency
    }

    private var phase = Phase.awaitingPreface
    private var inbound: [UInt8] = []
    var writer = HTTP2FrameWriter()
    private var decoder: HPACKDecoder
    var encoder: HPACKEncoder
    var accumulator: HTTP2HeaderBlockAccumulator
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
    var pendingHeadersEndStream = false
    /// The deprecated priority-section stream dependency of the open HEADERS block, if any (RFC 9113
    /// §5.3.2) — captured when the HEADERS frame arrives, checked after the block decodes so a
    /// self-dependency is rejected as a stream error without desyncing the HPACK table (§5.3.1).
    var pendingHeadersDependency: HTTP2StreamID?
    var lastPeerStreamID = HTTP2StreamID(0)
    /// How each recently-closed client stream id reached the closed state — a bounded FIFO (§5.1).
    ///
    /// A late DATA on any closed id is a survivable STREAM_CLOSED *stream* error; a HEADERS reusing an
    /// id closed by END_STREAM is a *connection* error STREAM_CLOSED (the id cannot reopen, RFC 9113
    /// §5.1), while one on an id closed by RST_STREAM stays a stream error (audit F1). A never-opened /
    /// unexpected id is a connection PROTOCOL_ERROR (§5.1.1). Bounded by the concurrency cap.
    enum StreamCloseReason: Sendable {
        /// Closed by END_STREAM on both sides — a HEADERS reuse is a connection error (§5.1).
        case endStream
        /// Closed by RST_STREAM (peer- or engine-sent) — a late frame is a survivable stream error (F1).
        case reset
    }

    private var closedStreams: [HTTP2StreamID: StreamCloseReason] = [:]
    private var closedStreamOrder: [HTTP2StreamID] = []
    // The abuse-budget state below is internal (not private) so the charge/decay helpers can live in
    // HTTP2Connection+AbuseBudget.swift.
    var activeStreamResets = 0
    /// Monotonic clock and rolling-window start for the abuse budgets (Rapid-Reset / MadeYouReset
    /// rate limiting, RFC 9113).
    ///
    /// The budgets reset every `streamResetInterval`, so a cap is a *rate* over that interval, not a
    /// per-connection total — closing both the long-window bypass and the false positive against a
    /// legitimately long-lived connection.
    let now: MonotonicNowProvider
    /// The rolling window the reset + control-frame budgets decay over (`streamResetInterval`).
    var budgetWindow: RollingWindow
    /// Leaky-bucket budget for ACK-generating control frames (PING / SETTINGS).
    ///
    /// Each charges it and a completed request drains it; a flood with no useful work in between
    /// trips ENHANCE_YOUR_CALM (RFC 9113 §6.5 / §6.7).
    var controlFrameBudget = 0
    var remoteSettings = HTTP2Settings()
    private let frameDecoder: HTTP2FrameDecoder
    let localSettings: HTTP2Settings
    let limits: HTTPLimits
    /// The concurrent-stream cap advertised to and enforced against the peer (RFC 9113 §5.1.2).
    let maxConcurrentStreams: Int

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
            maxDynamicTableSize: advertised.headerTableSize,
            limits: limits
        )
        self.encoder = HPACKEncoder(maxDynamicTableSize: remoteSettings.headerTableSize)
        self.accumulator = HTTP2HeaderBlockAccumulator(
            maxContinuationFrames: limits.maxContinuationFrames,
            maxBlockSize: limits.maxHeaderListSize
        )
        self.frameDecoder = HTTP2FrameDecoder(maxFrameSize: advertised.maxFrameSize)
        self.now = now
        self.budgetWindow = RollingWindow(
            start: now(), interval: limits.streamResetInterval.monotonicNanoseconds
        )
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
                guard try consumePreface() else {
                    return []
                }
            }
            var events: [Event] = []
            for frame in try drainFrames() {
                try process(frame, into: &events)
            }
            return events
        }
        catch {
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
        guard try result.get() else {
            return false
        }
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
                    var frames: [HTTP2FrameDecoder.Frame] = []
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
        }
        catch {
            // A stream-scoped error resets just that stream and the connection continues (RFC 9113
            // §5.4.2); a connection-scoped error propagates to GOAWAY + close (§5.4.1).
            guard let streamID = error.streamID else { throw error }
            writer.writeRstStream(streamID, code: error.code)
            streams[streamID] = nil
            markStreamClosed(streamID, reason: .reset)
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
            case .headers:
                try receiveHeaders(frame, into: &events)
            case .continuation:
                try receiveContinuation(frame, into: &events)
            case .data:
                try receiveData(frame, into: &events)
            case .settings:
                try applySettings(frame)
            case .ping:
                try receivePing(frame)
            case .rstStream:
                try receiveReset(frame, into: &events)
            case .windowUpdate:
                try receiveWindowUpdate(frame)
            case .priority:
                try receivePriority(frame)
            case .goAway:
                try receiveGoAway(frame)
            case .pushPromise:
                throw .connection(
                    .protocolError,
                    "a client must not send PUSH_PROMISE (RFC 9113 §8.4)"
                )
            default:
                break  // unknown frame types MUST be ignored (RFC 9113 §4.1)
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

    // MARK: Helpers

    /// Records `streamID` as recently closed with *how* it closed (bounded FIFO), so a later frame on
    /// it is scoped per RFC 9113 §5.1 (audit F1): a stream error for an RST-closed id or a late DATA, a
    /// connection error for a HEADERS reuse of an END_STREAM-closed id.
    mutating func markStreamClosed(_ streamID: HTTP2StreamID, reason: StreamCloseReason) {
        guard closedStreams[streamID] == nil else {
            return
        }
        closedStreams[streamID] = reason
        closedStreamOrder.append(streamID)
        if closedStreamOrder.count > maxConcurrentStreams {
            closedStreams[closedStreamOrder.removeFirst()] = nil
        }
    }

    /// Whether `streamID` was recently closed (opened then gone), per RFC 9113 §5.1.
    func isRecentlyClosed(_ streamID: HTTP2StreamID) -> Bool { closedStreams[streamID] != nil }

    /// How `streamID` was closed, if it is in the recently-closed set (RFC 9113 §5.1).
    func closeReason(of streamID: HTTP2StreamID) -> StreamCloseReason? { closedStreams[streamID] }

    mutating func emitRequest(
        _ streamID: HTTP2StreamID, into events: inout [Event]
    )
        throws(HTTP2Error)
    {
        guard let record = streams[streamID] else {
            return
        }
        try validateContentLength(record)
        controlFrameBudget = max(0, controlFrameBudget - 1)  // useful work drains the flood budget
        events.append(.request(streamID: streamID, request: record.request, body: record.body))
        // The body now belongs to the dispatched event; drop the engine's copy so a half-closed stream
        // awaiting its response holds no duplicate and the connection body budget
        // (HTTP2Connection+FlowControl) counts only still-accumulating streams, not dispatched ones.
        streams[streamID]?.body = []
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
                        record.stream.id,
                        .protocolError,
                        "content-length does not match body"
                    )
                }
        }
    }

    mutating func decodeHeaderBlock(_ block: [UInt8]) throws(HTTP2Error) -> [HPACKField] {
        let decoded: Result<[HPACKField], HPACKError> = block.withUnsafeBytes { raw in
            Result { () throws(HPACKError) in try decoder.decode(raw.bytes) }
        }
        switch decoded {
            case .success(let fields):
                return fields
            case .failure:
                throw .connection(.compressionError, "HPACK decoding failed")
        }
    }
}
