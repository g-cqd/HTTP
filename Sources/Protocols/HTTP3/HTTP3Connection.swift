//
//  HTTP3Connection.swift
//  HTTP3
//
//  RFC 9114 — the sans-I/O HTTP/3 server connection engine. It is a pure, per-stream state machine:
//  QUIC delivers bytes per stream (unlike HTTP/2's single demultiplexed octet stream), so the driver
//  feeds `receive(streamID:bytes:fin:)` and drains role-addressed `outbound()` actions. The engine
//  knows stream *semantics*; the transport owns stream *id allocation* — so outbound actions are
//  addressed by realized id or by role (the control + QPACK streams are queued at init, §3.2, before
//  QUIC has minted their ids; the driver resolves `.role` once it opens them).
//
//  This file holds the core: the public API, the connection state, init-time SETTINGS, the receive/
//  reset/outbound entry points, and error scoping. The control / QPACK / request stream handling lives
//  in HTTP3Connection+Streams.swift; response encoding in HTTP3Connection+Response.swift.
//

public import HTTPConcurrency
public import HTTPCore
internal import QPACK

/// A sans-I/O HTTP/3 server connection (RFC 9114): feed it per-stream octets, drain actions, collect
/// events.
public struct HTTP3Connection {
    /// A high-level event surfaced to the connection driver.
    public enum Event: Sendable, Equatable {
        /// A complete request arrived on a request stream (HEADERS and any DATA received, RFC 9114 §4).
        case request(streamID: QUICStreamID, request: HTTPRequest, body: [UInt8])
        /// An Extended CONNECT opened a tunnel on a request stream (RFC 9220 / RFC 8441 §4) — `protocol`
        /// names it (e.g. `"websocket"`). The driver accepts with ``acceptTunnel(_:secWebSocketExtensions:)``
        /// or resets the stream. Surfaced as soon as the CONNECT HEADERS decode — it does not await FIN.
        case extendedConnect(streamID: QUICStreamID, request: HTTPRequest, protocol: String)
        /// Opaque bytes arrived on a tunnel stream's DATA frames (RFC 9220 / RFC 8441 §5).
        case tunnelData(streamID: QUICStreamID, bytes: [UInt8])
        /// The peer ended a tunnel stream with FIN (RFC 9220 / RFC 8441 §5).
        case tunnelClosed(streamID: QUICStreamID)
        /// The peer sent GOAWAY, asking us to stop opening streams above `streamID` (RFC 9114 §5.2).
        case goAway(streamID: QUICStreamID)
    }

    /// Where an outbound `send` is directed: a realized stream id, or a not-yet-opened role.
    public enum StreamTarget: Sendable, Equatable {
        /// A stream by its realized QUIC id (e.g. a request stream we are responding on).
        case id(QUICStreamID)
        /// A stream by role — the driver resolves it to the id it minted for that role (RFC 9114 §3.2).
        case role(HTTP3StreamRole)
    }

    /// An outbound action for the driver to perform on the QUIC connection.
    public enum Action: Sendable, Equatable {
        /// Open a unidirectional stream for `role`, writing `preamble` first — the §6.2 Stream Type
        /// byte, plus the SETTINGS frame for the control stream (RFC 9114 §6.2.1).
        case openUniStream(role: HTTP3StreamRole, preamble: [UInt8])
        /// Send `bytes` on a stream, ending it with FIN when `fin` is set.
        case send(stream: StreamTarget, bytes: [UInt8], fin: Bool)
        /// Abruptly reset a request stream with a QUIC application error code (RFC 9114 §8).
        case resetStream(streamID: QUICStreamID, errorCode: UInt64)
        /// Close the whole connection with a QUIC application error code (CONNECTION_CLOSE).
        case closeConnection(errorCode: UInt64)
    }

    /// Whether a registered stream is bidirectional (a request) or unidirectional (control/QPACK/…).
    public enum StreamDirection: Sendable, Equatable {
        case bidirectional
        case unidirectional
    }

    /// The classified role of a peer stream within the engine.
    enum StreamKind: Sendable, Equatable {
        case unclassifiedUni  // a unidirectional stream whose §6.2 type byte has not been read yet
        case control
        case qpackEncoder
        case qpackDecoder
        case reserved  // an unknown unidirectional stream type — data is discarded
        case request  // a client-initiated bidirectional request stream
    }

    /// Per-stream receive state: the classified kind, the unconsumed byte buffer, and FIN.
    struct StreamState: Sendable {
        var kind: StreamKind
        var buffer: [UInt8] = []
        var finReceived = false
        /// Whether the request HEADERS have been seen on a request stream (DATA-before-HEADERS guard,
        /// RFC 9114 §4.1).
        var sawHeaders = false
        /// Whether a trailing HEADERS block (trailers) has been seen — no frame may follow it (§4.1).
        var sawTrailers = false
        /// Whether the completed request has already been surfaced as an event (emit-once guard).
        var requestEmitted = false
        /// Extended CONNECT (RFC 9220): this request stream is a tunnel — its DATA frames are opaque
        /// tunnel bytes (not a request body), and FIN is `tunnelClosed`, not end-of-request.
        var isTunnel = false
        /// The Extended CONNECT `:protocol` (e.g. `"websocket"`), surfaced with `extendedConnect`.
        var connectProtocol: String?
        /// Whether the `extendedConnect` event has been surfaced (emit-once guard for the tunnel open).
        var tunnelAnnounced = false
        /// The request being assembled on a request stream, and its body.
        var request: HTTPRequest?
        var body: [UInt8] = []
        /// A request HEADERS section referencing dynamic-table entries not yet received, buffered with
        /// its Required Insert Count until the encoder stream delivers those inserts and the stream
        /// decodes once `insertCount ≥ RIC` (RFC 9204 §2.1.2 blocked stream).
        var blockedSection: (payload: [UInt8], requiredInsertCount: Int)?
    }

    let localSettings: HTTP3Settings
    let limits: HTTPLimits
    var decoder: QPACKDecoder
    var encoder: QPACKEncoder
    let frameDecoder: HTTP3FrameDecoder

    /// Queued outbound actions, drained by ``outbound()``.
    var actions: [Action] = []
    /// Per-stream receive state, keyed by QUIC stream id, with O(1) running buffered-body and
    /// blocked-section totals for the connection-wide budgets (see ``HTTP3StreamTable``).
    var streams = HTTP3StreamTable()

    /// The peer's critical stream ids — each a singleton; a second of any kind is a creation error.
    var peerControlStream: QUICStreamID?
    var peerQpackEncoderStream: QUICStreamID?
    var peerQpackDecoderStream: QUICStreamID?
    /// Whether the peer's control stream has delivered its mandatory first SETTINGS frame (§6.2.1).
    var peerSettingsReceived = false
    /// The peer's settings, applied from its SETTINGS frame.
    var remoteSettings = HTTP3Settings()
    /// The last GOAWAY id received — a subsequent GOAWAY must not increase it (RFC 9114 §5.2).
    var lastGoAwayID: UInt64?
    /// The highest MAX_PUSH_ID received — it must not decrease (RFC 9114 §7.2.7).
    var maxPushID: UInt64?
    /// The injected monotonic clock the reset rolling window is measured against (RFC 9114 §8.1).
    let now: MonotonicNowProvider
    /// The rolling window the reset budget decays over (`limits.streamResetInterval`).
    var budgetWindow: RollingWindow
    /// Stream resets charged in the current window — peer RESET_STREAM and engine-emitted alike, so
    /// neither Rapid Reset (CVE-2023-44487) nor MadeYouReset (CVE-2025-8671) can bypass the cap.
    var streamResetCount = 0

    /// The dynamic QPACK table capacity advertised when the caller does not pin one (RFC 9204 §3.2.3) —
    /// a modest default that lets a peer encoder compress requests without unbounded decoder memory.
    static let defaultQpackMaxTableCapacity = 4_096

    /// The number of streams that may be blocked on not-yet-received inserts at once (RFC 9204 §2.1.2 /
    /// SETTINGS_QPACK_BLOCKED_STREAMS) — a bound on the buffered-blocked-section memory.
    static let defaultQpackBlockedStreams = 16

    /// Creates a connection advertising `localSettings`, queuing the control + QPACK streams (§3.2).
    ///
    /// `now` is the monotonic clock the Rapid-Reset / MadeYouReset rolling window is measured against;
    /// it defaults to the live clock and a test injects a controllable one.
    public init(
        localSettings: HTTP3Settings = HTTP3Settings(),
        limits: HTTPLimits = .default,
        now: @escaping MonotonicNowProvider = LiveMonotonicClock.now
    ) {
        // Advertise a dynamic QPACK table the peer encoder may populate (RFC 9204 §3.2); a caller can
        // pin `qpackMaxTableCapacity` to 0 for static-only decoding. With blocked streams permitted
        // (§2.1.2) the decoder buffers a request that references inserts not yet received and decodes it
        // once they arrive; the decode bound is surfaced as MAX_FIELD_SECTION_SIZE.
        var advertised = localSettings
        if advertised.qpackMaxTableCapacity == 0 {
            advertised.qpackMaxTableCapacity = Self.defaultQpackMaxTableCapacity
            advertised.qpackBlockedStreams = Self.defaultQpackBlockedStreams
        }
        if advertised.maxFieldSectionSize == nil {
            advertised.maxFieldSectionSize = limits.maxHeaderListSize
        }
        self.localSettings = advertised
        self.limits = limits
        self.decoder = QPACKDecoder(
            maxTableCapacity: advertised.qpackMaxTableCapacity, limits: limits
        )
        self.encoder = QPACKEncoder()
        // Bound a single frame's payload; HEADERS is bounded by the field-section size, and DATA is
        // streamed in +Streams, so the header-list size is a safe ceiling for the control plane.
        self.frameDecoder = HTTP3FrameDecoder(maxFrameSize: limits.maxHeaderListSize)
        self.now = now
        self.budgetWindow = RollingWindow(
            start: now(), interval: limits.streamResetInterval.monotonicNanoseconds
        )
        // RFC 9114 §6.2.1 — the control stream opens with its type byte (0x00) then the SETTINGS frame;
        // §4.2 / RFC 9204 §4.2 — the QPACK encoder (0x02) and decoder (0x03) streams open with just
        // their type byte. We send no encoder-stream instructions yet (our *response* encoder is still
        // static-only); the peer's encoder may use the dynamic table we advertised, decoded inbound.
        let settingsFrame = HTTP3FrameWriter.frame(.settings, payload: advertised.encodePayload())
        actions.append(.openUniStream(role: .control, preamble: [0x00] + settingsFrame))
        actions.append(.openUniStream(role: .qpackEncoder, preamble: [0x02]))
        actions.append(.openUniStream(role: .qpackDecoder, preamble: [0x03]))
    }

    /// Registers a newly opened peer stream so the engine tracks it before bytes arrive.
    ///
    /// Optional — ``receive(_:_:fin:)`` auto-registers from the stream id's class — but the driver may
    /// call it as soon as QUIC surfaces the stream.
    public mutating func registerStream(_ id: QUICStreamID, direction: StreamDirection) {
        guard streams[id] == nil else {
            return
        }
        streams[id] = StreamState(kind: direction == .unidirectional ? .unclassifiedUni : .request)
    }

    /// Drains the queued outbound actions for the driver to perform.
    public mutating func outbound() -> [Action] {
        var drained: [Action] = []
        swap(&drained, &actions)
        return drained
    }

    /// Feeds inbound octets for one stream, with `fin` marking the stream's end, and returns any events
    /// they complete (RFC 9114).
    ///
    /// A connection-scoped error is fatal: it queues CONNECTION_CLOSE and rethrows so the driver closes.
    /// A stream-scoped error resets just that stream and the connection continues.
    public mutating func receive(
        _ streamID: QUICStreamID,
        _ bytes: [UInt8],
        fin: Bool
    ) throws(HTTP3Error) -> [Event] {
        var events: [Event] = []
        do {
            try process(streamID, bytes, fin: fin, into: &events)
        }
        catch {
            guard error.isConnectionError else {
                if let streamID = error.streamID {
                    actions.append(.resetStream(streamID: streamID, errorCode: error.code))
                    streams[streamID] = nil
                    chargeStreamReset()  // MadeYouReset parity: engine-emitted resets count too
                }
                return events
            }
            actions.append(.closeConnection(errorCode: error.code))
            throw error
        }
        return events
    }

    /// Reacts to a peer RESET_STREAM on `streamID` (RFC 9114 §8 / QUIC RESET_STREAM).
    ///
    /// Drops the stream and charges the Rapid Reset analog: too many resets of active streams trip
    /// H3_EXCESSIVE_LOAD, queuing CONNECTION_CLOSE for the driver (RFC 9114 §8.1).
    public mutating func resetStream(_ streamID: QUICStreamID, errorCode _: UInt64) -> [Event] {
        if let state = streams.removeValue(forKey: streamID), state.kind == .request {
            chargeStreamReset()
        }
        return []
    }

    /// Charges one stream reset against the rolling budget — a peer RESET_STREAM or an engine-emitted
    /// reset alike — queuing CONNECTION_CLOSE with H3_EXCESSIVE_LOAD past the cap (RFC 9114 §8.1).
    ///
    /// The count decays each `streamResetInterval` (a *rate*, not a per-connection total), and charging
    /// engine-emitted resets too mirrors the HTTP/2 abuse budget — so neither Rapid Reset
    /// (CVE-2023-44487) nor MadeYouReset (CVE-2025-8671) can bypass it.
    mutating func chargeStreamReset() {
        if budgetWindow.rolledOver(at: now()) {
            streamResetCount = 0
        }
        streamResetCount += 1
        if streamResetCount > limits.maxStreamResetsPerInterval {
            actions.append(.closeConnection(errorCode: HTTP3ErrorCode.h3ExcessiveLoad.rawValue))
        }
    }

    /// Dispatches buffered stream bytes to the handler for the stream's classified kind.
    private mutating func process(
        _ streamID: QUICStreamID,
        _ bytes: [UInt8],
        fin: Bool,
        into events: inout [Event]
    ) throws(HTTP3Error) {
        // RFC 9114 §6.1: HTTP/3 request streams are client-initiated bidirectional; the protocol does
        // not use server-initiated bidirectional streams. The sans-I/O engine validates the id class
        // itself rather than trusting the transport to deliver only client streams (audit P0-16).
        if streams[streamID] == nil, streamID.kind == .serverBidirectional {
            throw .connection(.h3StreamCreationError, "a server-initiated bidirectional stream")
        }
        var state =
            streams[streamID]
            ?? StreamState(
                kind: streamID.isUnidirectional ? .unclassifiedUni : .request
            )
        state.buffer.append(contentsOf: bytes)
        if fin { state.finReceived = true }
        streams[streamID] = state
        try dispatch(streamID, into: &events)
    }

    /// Reads a stream's classified kind and routes it to the matching handler (RFC 9114 §6).
    mutating func dispatch(
        _ streamID: QUICStreamID,
        into events: inout [Event]
    ) throws(HTTP3Error) {
        guard let kind = streams[streamID]?.kind else {
            return
        }
        try dispatchClassified(streamID, kind: kind, into: &events)
    }

    /// Runs the handler for a stream's classified `kind` (the handlers live in +Streams / +Request).
    ///
    /// A still-`unclassifiedUni` unidirectional stream goes to ``classifyUniStream(_:into:)``, which
    /// reads its §6.2 Stream Type and then routes the buffered remainder back here directly under the
    /// now-known kind — so classification never re-enters ``dispatch(_:into:)`` (the engine stays
    /// recursion-free).
    mutating func dispatchClassified(
        _ streamID: QUICStreamID,
        kind: StreamKind,
        into events: inout [Event]
    ) throws(HTTP3Error) {
        switch kind {
            case .unclassifiedUni:
                try classifyUniStream(streamID, into: &events)
            case .control:
                try processControlStream(streamID, into: &events)
            case .qpackEncoder:
                try processQpackEncoderStream(streamID, into: &events)
            case .qpackDecoder:
                try processQpackDecoderStream(streamID)
            case .reserved:
                // §6.2 — an unknown unidirectional stream type: discard its buffered data.
                streams[streamID]?.buffer.removeAll(keepingCapacity: false)
            case .request:
                try processRequestStream(streamID, into: &events)
        }
    }
}
