//
//  WebSocketFrame.swift
//  WebSocket
//
//  RFC 6455 §5.2 — one decoded WebSocket frame: the FIN bit, the opcode, and the unmasked payload.
//  Masking (§5.3) is a wire concern resolved by the decoder/encoder, so it is absent here: a frame
//  always presents its application payload in the clear.
//

/// A single decoded WebSocket frame (RFC 6455 §5.2), payload already unmasked.
public struct WebSocketFrame: Sendable, Equatable {

    /// The FIN bit: whether this frame is the final fragment of its message (RFC 6455 §5.4).
    public var isFinal: Bool

    /// The frame opcode (RFC 6455 §5.2).
    public var opcode: WebSocketOpcode

    /// The application payload, unmasked (RFC 6455 §5.3).
    public var payload: [UInt8]

    /// Creates a frame from its FIN bit, opcode, and unmasked payload.
    public init(isFinal: Bool = true, opcode: WebSocketOpcode, payload: [UInt8] = []) {
        self.isFinal = isFinal
        self.opcode = opcode
        self.payload = payload
    }
}
