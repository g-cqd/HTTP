//
//  HTTP2FrameFlags.swift
//  HTTP2
//
//  RFC 9113 §4.1 — the 8-bit frame flags field. Flag meaning is type-specific; the same bit denotes
//  END_STREAM on DATA/HEADERS and ACK on SETTINGS/PING, so the constants are named per their use.
//

/// The HTTP/2 frame flags bitfield (RFC 9113 §4.1), interpreted per frame type.
public struct HTTP2FrameFlags: OptionSet, Sendable, Equatable, Hashable {
    /// The raw 8-bit flags value.
    public let rawValue: UInt8

    /// Creates a flag set from its wire value.
    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }

    /// `END_STREAM` (0x01) on DATA and HEADERS (RFC 9113 §6.1 / §6.2).
    public static let endStream = Self(rawValue: 0x01)
    /// `ACK` (0x01) on SETTINGS and PING (RFC 9113 §6.5 / §6.7).
    public static let ack = Self(rawValue: 0x01)
    /// `END_HEADERS` (0x04) on HEADERS, PUSH_PROMISE, and CONTINUATION (RFC 9113 §6.2 / §6.10).
    public static let endHeaders = Self(rawValue: 0x04)
    /// `PADDED` (0x08) on DATA, HEADERS, and PUSH_PROMISE (RFC 9113 §6.1 / §6.2).
    public static let padded = Self(rawValue: 0x08)
    /// `PRIORITY` (0x20) on HEADERS (RFC 9113 §6.2).
    public static let priority = Self(rawValue: 0x20)
}
