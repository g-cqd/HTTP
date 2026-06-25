//
//  WebSocketConnection.swift
//  WebSocket
//
//  RFC 6455 §5 / §6 — the sans-I/O server connection engine. Fed inbound octets, it decodes frames,
//  reassembles fragmented messages (§5.4), answers Ping with Pong (§5.5.2), runs the closing
//  handshake (§5.5.1), and validates text as UTF-8 (§8.1) and Close codes (§7.4.1) — surfacing
//  high-level events. Queued frames (Pongs, Close echoes, application messages) drain with
//  `outboundBytes`. No sockets, no concurrency; the driver owns one instance per connection.
//

internal import HTTPCore

/// A sans-I/O WebSocket server connection (RFC 6455): feed octets, drain octets, collect events.
public struct WebSocketConnection {
    /// A high-level event surfaced to the connection driver.
    public enum Event: Sendable, Equatable {
        /// A complete message arrived (all fragments reassembled) — text or binary (RFC 6455 §5.6).
        case message(opcode: WebSocketOpcode, payload: [UInt8])

        /// A Ping arrived; the engine has already queued the matching Pong (RFC 6455 §5.5.2).
        case ping([UInt8])

        /// A Pong arrived (RFC 6455 §5.5.3).
        case pong([UInt8])

        /// A Close arrived; the engine has echoed a Close if it had not already sent one (§5.5.1).
        case close(code: WebSocketCloseCode?, reason: [UInt8])
    }

    private let decoder: WebSocketFrameDecoder
    private let encoder = WebSocketFrameEncoder()
    private let maxMessageSize: Int
    /// Whether permessage-deflate was negotiated (RFC 7692 §5.1) — true iff ``codec`` is present.
    ///
    /// Outbound messages are then compressed with RSV1 set, and an inbound RSV1 message is inflated
    /// before delivery.
    private let permessageDeflate: Bool
    /// The permessage-deflate codec for this connection (RFC 7692), or nil when not negotiated.
    private let codec: PermessageDeflate?
    private var inbound: [UInt8] = []
    private var output: [UInt8] = []
    private var closeSent = false
    /// The opcode of the message currently being reassembled, or nil when none is open (RFC 6455 §5.4).
    private var fragmentOpcode: WebSocketOpcode?
    private var fragments: [UInt8] = []
    /// Whether the message currently being reassembled was flagged compressed by RSV1 on its first
    /// frame (RFC 7692 §6) — so its fragments are inflated, not UTF-8-validated, until reassembled.
    private var messageCompressed = false
    /// Incremental UTF-8 state for the in-flight text message, so an invalid sequence is rejected at the
    /// first bad octet across fragments rather than after the whole message buffers (RFC 6455 §8.1).
    ///
    /// Bypassed for a compressed message, whose fragments are ciphertext until inflated (RFC 7692 §7.2).
    private var textValidator = IncrementalUTF8Validator()

    /// Creates a server connection, requiring masked client frames (RFC 6455 §5.1).
    ///
    /// Bounds a single frame to `maxFrameSize` and a reassembled message to `maxMessageSize`
    /// (resource-exhaustion guards); pass the negotiated `permessageDeflate` parameters to enable that
    /// extension (RFC 7692 §5.1), or nil for an uncompressed connection.
    public init(
        maxFrameSize: Int = 1 << 20,
        maxMessageSize: Int = 16 << 20,
        permessageDeflate: PermessageDeflateParameters? = nil
    ) {
        // The codec owns zlib state; if it fails to initialize (OOM), fall back to no compression so the
        // connection stays well-formed rather than half-enabled.
        let codec = permessageDeflate.flatMap { PermessageDeflate(parameters: $0) }
        self.decoder = WebSocketFrameDecoder(
            maxPayloadLength: maxFrameSize,
            requireMaskedFrames: true,
            permessageDeflate: codec != nil
        )
        self.maxMessageSize = maxMessageSize
        self.permessageDeflate = codec != nil
        self.codec = codec
    }

    /// Whether the engine has sent a Close frame; the driver should flush and close once it has.
    public var isClosing: Bool { closeSent }

    // MARK: Receive

    /// Feeds inbound octets and returns the events they complete (RFC 6455 §6.2).
    ///
    /// On a protocol violation it queues a Close frame carrying the mapped status (§7.4.1) — so the
    /// driver can flush it before closing — and rethrows.
    public mutating func receive(_ bytes: some Collection<UInt8>) throws(WebSocketError) -> [Event]
    {
        do {
            inbound.append(contentsOf: bytes)
            var events: [Event] = []
            for frame in try drainFrames() { try process(frame, into: &events) }
            return events
        }
        catch {
            queueClose(error.closeCode)
            throw error
        }
    }

    /// Drains the queued outbound octets (Pongs, Close echoes, application messages).
    public mutating func outboundBytes() -> [UInt8] {
        defer { output.removeAll(keepingCapacity: true) }
        return output
    }

    // MARK: Send

    /// Queues a text message (RFC 6455 §5.6); ignored once a Close has been sent (§5.5.1).
    public mutating func send(text: String) {
        queueDataMessage(opcode: .text, payload: Array(text.utf8))
    }

    /// Queues a binary message (RFC 6455 §5.6); ignored once a Close has been sent (§5.5.1).
    public mutating func send(binary: [UInt8]) {
        queueDataMessage(opcode: .binary, payload: binary)
    }

    /// Queues a data message, compressing it with RSV1 set when permessage-deflate was negotiated
    /// (RFC 7692 §6, `no_context_takeover`); falls back to an uncompressed frame when the extension is
    /// off or compression fails (which the spec permits — RSV1 then stays clear).
    private mutating func queueDataMessage(opcode: WebSocketOpcode, payload: [UInt8]) {
        guard let codec, let compressed = codec.compress(payload) else {
            queue(WebSocketFrame(opcode: opcode, payload: payload))
            return
        }
        queue(WebSocketFrame(rsv1: true, opcode: opcode, payload: compressed))
    }

    /// Queues a Ping with an optional application payload (RFC 6455 §5.5.2).
    public mutating func sendPing(_ payload: [UInt8] = []) {
        queue(WebSocketFrame(opcode: .ping, payload: payload))
    }

    /// Initiates the closing handshake with `code` and an optional `reason` (RFC 6455 §5.5.1).
    public mutating func close(_ code: WebSocketCloseCode = .normalClosure, reason: String = "") {
        guard !closeSent else {
            return
        }
        closeSent = true
        // §7.4.1 — never put a code that must not appear on the wire (1005/1006/1015/undefined) out.
        let safeCode = code.isValidOnWire ? code : .protocolError
        // §5.5 — a control frame's payload is ≤125 octets; the 2-octet code leaves ≤123 for the reason.
        let reasonBytes = Self.truncatedUTF8(Array(reason.utf8), maxBytes: 123)
        let payload = Self.closePayload(safeCode, reason: reasonBytes)
        output += encoder.encode(WebSocketFrame(opcode: .close, payload: payload))
    }

    // MARK: Frame handling

    private mutating func process(
        _ frame: WebSocketFrame,
        into events: inout [Event]
    ) throws(WebSocketError) {
        if frame.opcode.isControl {
            try processControl(frame, into: &events)
        }
        else {
            try processData(frame, into: &events)
        }
    }

    private mutating func processControl(
        _ frame: WebSocketFrame,
        into events: inout [Event]
    ) throws(WebSocketError) {
        switch frame.opcode {
            case .ping:
                // §5.5.2 — MUST reply with a Pong. After a Close is received we have already echoed a
                // Close (setting closeSent), so `queue` here suppresses the Pong — the §5.5.2 exception.
                queue(WebSocketFrame(opcode: .pong, payload: frame.payload))
                events.append(.ping(frame.payload))
            case .pong:
                events.append(.pong(frame.payload))
            case .close:
                let (code, reason) = try Self.parseClose(frame.payload)
                if !closeSent { queueClose(code ?? .normalClosure) }  // §5.5.1 — echo a Close
                events.append(.close(code: code, reason: reason))
            default:
                break  // unreachable: a defined control opcode is ping/pong/close
        }
    }

    private mutating func processData(
        _ frame: WebSocketFrame,
        into events: inout [Event]
    ) throws(WebSocketError) {
        if frame.opcode == .continuation {
            guard let opcode = fragmentOpcode else { throw .unexpectedContinuation }  // §5.4
            guard !frame.rsv1 else { throw .reservedBitsSet }  // RSV1 only on the first frame (§6)
            try appendFragment(frame.payload, isText: opcode == .text && !messageCompressed)
            guard frame.isFinal else {
                return
            }
            try finishFragmentedMessage(opcode: opcode, into: &events)
            return
        }
        guard fragmentOpcode == nil else { throw .interleavedDataFrame }  // §5.4
        if frame.isFinal {
            // A single-frame message: inflate it when RSV1 marks it compressed, else the fast path.
            if frame.rsv1 {
                try emitDecompressed(opcode: frame.opcode, deflated: frame.payload, into: &events)
            }
            else {
                try emitUnfragmented(opcode: frame.opcode, payload: frame.payload, into: &events)
            }
        }
        else {
            fragmentOpcode = frame.opcode
            // RSV1 on the first frame marks the whole message compressed (RFC 7692 §6).
            messageCompressed = frame.rsv1
            if frame.opcode == .text, !frame.rsv1 {
                textValidator = IncrementalUTF8Validator()  // reset for the new (uncompressed) text
            }
            try appendFragment(frame.payload, isText: frame.opcode == .text && !frame.rsv1)
        }
    }

    /// Completes a reassembled fragmented message: inflate it when RSV1 marked it compressed (RFC 7692
    /// §7.2.2), else apply the §8.1 final UTF-8 boundary check, then emit it.
    private mutating func finishFragmentedMessage(
        opcode: WebSocketOpcode,
        into events: inout [Event]
    ) throws(WebSocketError) {
        let deflated = fragments
        let compressed = messageCompressed
        fragmentOpcode = nil
        fragments = []
        messageCompressed = false
        if compressed {
            try emitDecompressed(opcode: opcode, deflated: deflated, into: &events)
            return
        }
        // §8.1 — a completed text message must end on a scalar boundary (no trailing partial scalar).
        guard opcode != .text || textValidator.isComplete else { throw .invalidTextEncoding }
        events.append(.message(opcode: opcode, payload: deflated))
    }

    /// Inflates a permessage-deflate message under the message cap (CWE-409), validates a text payload
    /// as UTF-8 *after* inflation (RFC 7692 §7.2.2 / RFC 6455 §8.1 — the compressed octets are not
    /// themselves text), and emits it.
    private func emitDecompressed(
        opcode: WebSocketOpcode,
        deflated: [UInt8],
        into events: inout [Event]
    ) throws(WebSocketError) {
        guard let codec, let payload = codec.decompress(deflated, maxSize: maxMessageSize) else {
            throw .invalidCompressedData
        }
        guard opcode != .text || Self.isValidUTF8(payload) else { throw .invalidTextEncoding }
        events.append(.message(opcode: opcode, payload: payload))
    }

    private mutating func appendFragment(_ payload: [UInt8], isText: Bool) throws(WebSocketError) {
        guard fragments.count + payload.count <= maxMessageSize else { throw .messageTooLarge }
        // §8.1 — validate text incrementally so an invalid sequence is rejected at the first bad octet,
        // not after the whole (up to `maxMessageSize`) message has been buffered.
        if isText {
            guard textValidator.consume(payload) else { throw .invalidTextEncoding }
        }
        fragments.append(contentsOf: payload)
    }

    /// Emits an unfragmented (single-frame) message, validating a text payload as UTF-8 (RFC 6455 §8.1).
    private func emitUnfragmented(
        opcode: WebSocketOpcode,
        payload: [UInt8],
        into events: inout [Event]
    ) throws(WebSocketError) {
        guard opcode != .text || Self.isValidUTF8(payload) else { throw .invalidTextEncoding }
        events.append(.message(opcode: opcode, payload: payload))
    }

    // MARK: Outbound + parsing helpers

    private mutating func queue(_ frame: WebSocketFrame) {
        guard !closeSent else {
            return  // §5.5.1 — nothing follows a Close
        }
        output += encoder.encode(frame)
    }

    private mutating func queueClose(_ code: WebSocketCloseCode) {
        guard !closeSent else {
            return
        }
        closeSent = true
        output += encoder.encode(
            WebSocketFrame(opcode: .close, payload: Self.closePayload(code, reason: []))
        )
    }

    private static func closePayload(_ code: WebSocketCloseCode, reason: [UInt8]) -> [UInt8] {
        var payload = [UInt8(code.rawValue >> 8), UInt8(code.rawValue & 0xFF)]
        payload.append(contentsOf: reason)
        return payload
    }

    /// Truncates `bytes` to at most `maxBytes`, backing off to a UTF-8 scalar boundary so a multi-byte
    /// sequence is never split (RFC 3629) — used to keep a Close reason within the §5.5 control limit.
    private static func truncatedUTF8(_ bytes: [UInt8], maxBytes: Int) -> [UInt8] {
        guard bytes.count > maxBytes else {
            return bytes
        }
        var end = maxBytes
        while end > 0, bytes[end] & 0xC0 == 0x80 { end -= 1 }  // step back over continuation octets
        return Array(bytes[..<end])
    }

    /// Parses a Close frame body (RFC 6455 §5.5.1): empty, or a 2-octet code plus a UTF-8 reason.
    private static func parseClose(
        _ payload: [UInt8]
    ) throws(WebSocketError) -> (WebSocketCloseCode?, [UInt8]) {
        guard !payload.isEmpty else {
            return (nil, [])
        }
        guard payload.count >= 2 else { throw .malformedClosePayload }
        let code = WebSocketCloseCode(rawValue: UInt16(payload[0]) << 8 | UInt16(payload[1]))
        guard code.isValidOnWire else { throw .invalidCloseCode }  // §7.4.1
        let reason = Array(payload[2...])
        guard isValidUTF8(reason) else { throw .invalidTextEncoding }  // §8.1
        return (code, reason)
    }

    /// Whether `bytes` is well-formed UTF-8 (RFC 3629), allocation-free.
    ///
    /// A one-shot wrapper over ``IncrementalUTF8Validator`` for a complete payload (e.g. a Close
    /// reason): the whole input must consume cleanly *and* leave no trailing partial scalar.
    private static func isValidUTF8(_ bytes: [UInt8]) -> Bool {
        var validator = IncrementalUTF8Validator()
        return validator.consume(bytes) && validator.isComplete
    }

    // MARK: Frame decoding

    private mutating func drainFrames() throws(WebSocketError) -> [WebSocketFrame] {
        let decoded: Result<(frames: [WebSocketFrame], consumed: Int), WebSocketError> =
            inbound.withUnsafeBytes { raw in
                Result { () throws(WebSocketError) in
                    var reader = ByteReader(raw)
                    var frames: [WebSocketFrame] = []
                    while let frame = try decoder.nextFrame(&reader) { frames.append(frame) }
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
}
