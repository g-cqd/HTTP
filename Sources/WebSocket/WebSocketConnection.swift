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
    private var inbound: [UInt8] = []
    private var output: [UInt8] = []
    private var closeSent = false
    /// The opcode of the message currently being reassembled, or nil when none is open (RFC 6455 §5.4).
    private var fragmentOpcode: WebSocketOpcode?
    private var fragments: [UInt8] = []
    /// Incremental UTF-8 state for the in-flight text message, so an invalid sequence is rejected at the
    /// first bad octet across fragments rather than after the whole message buffers (RFC 6455 §8.1).
    private var textValidator = IncrementalUTF8Validator()

    /// Creates a server connection: it requires masked client frames (§5.1) and bounds a single frame
    /// to `maxFrameSize` and a reassembled message to `maxMessageSize` (resource-exhaustion guards).
    public init(maxFrameSize: Int = 1 << 20, maxMessageSize: Int = 16 << 20) {
        self.decoder = WebSocketFrameDecoder(
            maxPayloadLength: maxFrameSize,
            requireMaskedFrames: true
        )
        self.maxMessageSize = maxMessageSize
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
        queue(WebSocketFrame(opcode: .text, payload: Array(text.utf8)))
    }

    /// Queues a binary message (RFC 6455 §5.6); ignored once a Close has been sent (§5.5.1).
    public mutating func send(binary: [UInt8]) {
        queue(WebSocketFrame(opcode: .binary, payload: binary))
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
            try appendFragment(frame.payload, isText: opcode == .text)
            guard frame.isFinal else {
                return
            }
            // §8.1 — a completed text message must end on a scalar boundary (no trailing partial scalar).
            guard opcode != .text || textValidator.isComplete else { throw .invalidTextEncoding }
            let message = fragments
            fragmentOpcode = nil
            fragments = []
            events.append(.message(opcode: opcode, payload: message))
            return
        }
        guard fragmentOpcode == nil else { throw .interleavedDataFrame }  // §5.4
        if frame.isFinal {
            try emitUnfragmented(opcode: frame.opcode, payload: frame.payload, into: &events)
        }
        else {
            fragmentOpcode = frame.opcode
            if frame.opcode == .text {
                textValidator = IncrementalUTF8Validator()  // reset for the new text message
            }
            try appendFragment(frame.payload, isText: frame.opcode == .text)  // open the message
        }
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
