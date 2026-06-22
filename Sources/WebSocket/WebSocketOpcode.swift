//
//  WebSocketOpcode.swift
//  WebSocket
//
//  RFC 6455 §5.2 / §11.8 — the 4-bit frame opcode. A struct (not an enum) so an undefined opcode
//  round-trips as a value the decoder can reject, rather than failing to construct.
//

/// A WebSocket frame opcode (RFC 6455 §5.2).
public struct WebSocketOpcode: Sendable, Equatable, Hashable {

    /// The 4-bit opcode value.
    public let rawValue: UInt8

    /// Wraps a raw 4-bit opcode (only the low nibble is meaningful).
    public init(rawValue: UInt8) {
        self.rawValue = rawValue & 0x0F
    }

    /// A continuation of a fragmented message (RFC 6455 §5.4).
    public static let continuation = WebSocketOpcode(rawValue: 0x0)

    /// A text (UTF-8) data frame (RFC 6455 §5.6).
    public static let text = WebSocketOpcode(rawValue: 0x1)

    /// A binary data frame (RFC 6455 §5.6).
    public static let binary = WebSocketOpcode(rawValue: 0x2)

    /// A Close control frame (RFC 6455 §5.5.1).
    public static let close = WebSocketOpcode(rawValue: 0x8)

    /// A Ping control frame (RFC 6455 §5.5.2).
    public static let ping = WebSocketOpcode(rawValue: 0x9)

    /// A Pong control frame (RFC 6455 §5.5.3).
    public static let pong = WebSocketOpcode(rawValue: 0xA)

    /// Whether this is a control frame: opcodes `0x8`–`0xF` (RFC 6455 §5.5).
    ///
    /// Control frames carry connection state (close/ping/pong); the high opcode bit distinguishes
    /// them from data frames, which constrains them to ≤125-octet, unfragmented payloads (§5.5).
    public var isControl: Bool {
        rawValue & 0x08 != 0
    }

    /// Whether this opcode is one the protocol defines (RFC 6455 §11.8); the rest are reserved.
    public var isDefined: Bool {
        switch rawValue {
        case 0x0, 0x1, 0x2, 0x8, 0x9, 0xA: true
        default: false
        }
    }
}
