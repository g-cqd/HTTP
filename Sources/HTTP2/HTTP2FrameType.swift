//
//  HTTP2FrameType.swift
//  HTTP2
//
//  RFC 9113 §6 — the frame type octet. Modeled as a wrapper rather than a closed enum because §4.1
//  requires receivers to ignore frames of unknown type, so unknown values must be representable.
//

/// An HTTP/2 frame type (RFC 9113 §6); unknown values are representable and ignored (§4.1).
public struct HTTP2FrameType: Sendable, Equatable, Hashable, RawRepresentable {
    /// The 8-bit type value.
    public let rawValue: UInt8

    /// Creates a frame type from its wire value.
    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }

    /// `DATA` (RFC 9113 §6.1).
    public static let data = Self(rawValue: 0x0)
    /// `HEADERS` (RFC 9113 §6.2).
    public static let headers = Self(rawValue: 0x1)
    /// `PRIORITY` (RFC 9113 §6.3).
    public static let priority = Self(rawValue: 0x2)
    /// `RST_STREAM` (RFC 9113 §6.4).
    public static let rstStream = Self(rawValue: 0x3)
    /// `SETTINGS` (RFC 9113 §6.5).
    public static let settings = Self(rawValue: 0x4)
    /// `PUSH_PROMISE` (RFC 9113 §6.6).
    public static let pushPromise = Self(rawValue: 0x5)
    /// `PING` (RFC 9113 §6.7).
    public static let ping = Self(rawValue: 0x6)
    /// `GOAWAY` (RFC 9113 §6.8).
    public static let goAway = Self(rawValue: 0x7)
    /// `WINDOW_UPDATE` (RFC 9113 §6.9).
    public static let windowUpdate = Self(rawValue: 0x8)
    /// `CONTINUATION` (RFC 9113 §6.10).
    public static let continuation = Self(rawValue: 0x9)
}
