//
//  WebSocketCloseCode.swift
//  WebSocket
//
//  RFC 6455 §7.4 — the Close frame status code. A struct (not an enum) so an unregistered code
//  round-trips as a value the connection can validate against §7.4.1 rather than failing to build.
//

/// A WebSocket Close status code (RFC 6455 §7.4).
public struct WebSocketCloseCode: Sendable, Equatable, Hashable {
    /// The numeric status code.
    public let rawValue: UInt16

    /// Wraps a raw status code.
    public init(rawValue: UInt16) {
        self.rawValue = rawValue
    }

    /// `1000` — a normal closure (RFC 6455 §7.4.1).
    public static let normalClosure = Self(rawValue: 1_000)

    /// `1001` — the endpoint is going away (RFC 6455 §7.4.1).
    public static let goingAway = Self(rawValue: 1_001)

    /// `1002` — a protocol error (RFC 6455 §7.4.1).
    public static let protocolError = Self(rawValue: 1_002)

    /// `1003` — the endpoint received data it cannot accept (RFC 6455 §7.4.1).
    public static let unsupportedData = Self(rawValue: 1_003)

    /// `1007` — a message was not consistent with its type, e.g. non-UTF-8 text (RFC 6455 §7.4.1).
    public static let invalidPayloadData = Self(rawValue: 1_007)

    /// `1008` — the message violated a policy (RFC 6455 §7.4.1).
    public static let policyViolation = Self(rawValue: 1_008)

    /// `1009` — the message was too big to process (RFC 6455 §7.4.1).
    public static let messageTooBig = Self(rawValue: 1_009)

    /// `1011` — the server hit an unexpected condition (RFC 6455 §7.4.1).
    public static let internalError = Self(rawValue: 1_011)

    /// Whether this code may legitimately appear in a Close frame on the wire (RFC 6455 §7.4.1).
    ///
    /// The application range 1000–1003 and 1007–1011 is permitted, as is the registered (3000–3999)
    /// and private (4000–4999) space; the rest — including the "no code present" sentinels 1005/1006
    /// and the undefined 1004 — MUST NOT be sent and are rejected when received.
    public var isValidOnWire: Bool {
        switch rawValue {
            case 1_000 ... 1_003, 1_007 ... 1_011, 3_000 ... 4_999:
                true
            default:
                false
        }
    }
}
