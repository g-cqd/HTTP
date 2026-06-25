//
//  WebSocketFrame.swift
//  WebSocket
//
//  RFC 6455 §5.2 — one decoded WebSocket frame: the FIN bit, the RSV1 bit, the opcode, and the unmasked
//  payload. Masking (§5.3) is a wire concern resolved by the decoder/encoder, so it is absent here: a
//  frame always presents its application payload in the clear. RSV1 carries the permessage-deflate
//  "this message is compressed" signal (RFC 7692 §6); RSV2/RSV3 have no defined use and stay rejected.
//

/// A single decoded WebSocket frame (RFC 6455 §5.2), payload already unmasked.
public struct WebSocketFrame: Sendable, Equatable {
    /// The FIN bit: whether this frame is the final fragment of its message (RFC 6455 §5.4).
    public var isFinal: Bool

    /// The RSV1 bit: set on the first frame of a permessage-deflate-compressed message (RFC 7692 §6).
    ///
    /// The decoder accepts it only when permessage-deflate is negotiated and never on a control frame;
    /// the encoder writes it when set. RSV2/RSV3 remain reserved and are always rejected.
    public var rsv1: Bool

    /// The frame opcode (RFC 6455 §5.2).
    public var opcode: WebSocketOpcode

    /// The application payload, unmasked (RFC 6455 §5.3).
    public var payload: [UInt8]

    /// Creates a frame from its FIN bit, RSV1 bit, opcode, and unmasked payload.
    public init(
        isFinal: Bool = true,
        rsv1: Bool = false,
        opcode: WebSocketOpcode,
        payload: [UInt8] = []
    ) {
        self.isFinal = isFinal
        self.rsv1 = rsv1
        self.opcode = opcode
        self.payload = payload
    }
}
