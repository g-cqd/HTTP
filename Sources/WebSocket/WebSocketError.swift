//
//  WebSocketError.swift
//  WebSocket
//
//  RFC 6455 §5.2 / §5.5 — the protocol violations the frame decoder fails closed on, each mapped to
//  the Close status code (§7.4.1) the connection should report before closing.
//

/// A WebSocket framing violation (RFC 6455 §5), with the Close code it maps to (§7.4.1).
public enum WebSocketError: Error, Sendable, Equatable {

    /// A reserved bit (RSV1–RSV3) was set without a negotiated extension (RFC 6455 §5.2).
    case reservedBitsSet

    /// The opcode is one the protocol reserves (`0x3`–`0x7`, `0xB`–`0xF`) (RFC 6455 §5.2).
    case reservedOpcode(UInt8)

    /// A control frame carried more than 125 payload octets (RFC 6455 §5.5).
    case controlFrameTooLong

    /// A control frame was fragmented (FIN was clear) (RFC 6455 §5.5).
    case fragmentedControlFrame

    /// The payload length was not encoded in the minimal number of octets (RFC 6455 §5.2).
    case nonMinimalLength

    /// The 64-bit length had its reserved most-significant bit set (RFC 6455 §5.2).
    case lengthHighBitSet

    /// The payload exceeded the configured maximum — a resource-exhaustion guard.
    case payloadTooLong

    /// The Close status code to report for this violation before closing (RFC 6455 §7.4.1).
    public var closeCode: UInt16 {
        switch self {
        case .payloadTooLong: 1009  // Message Too Big
        default: 1002  // Protocol Error
        }
    }
}
