//
//  HTTP3FrameType.swift
//  HTTP3
//
//  RFC 9114 §7.2 / §11.2.1 — the HTTP/3 frame type, a variable-length integer. Modeled as a wrapper
//  rather than a closed enum because §9 requires receivers to ignore frames of unknown type (and the
//  reserved "grease" types 0x1f*N+0x21, §7.2.8), so unknown values must be representable. The type
//  values are sparse (0x02/0x06/0x08/0x09 are unassigned reserved values that map to HTTP/2 frames and
//  MUST be rejected on the control stream, §7.2.1).
//

/// An HTTP/3 frame type (RFC 9114 §7.2); a varint, with unknown values representable and ignored (§9).
public struct HTTP3FrameType: Sendable, Equatable, Hashable, RawRepresentable {
    /// The frame type value (a variable-length integer).
    public let rawValue: UInt64

    /// Creates a frame type from its wire value.
    public init(rawValue: UInt64) {
        self.rawValue = rawValue
    }

    /// `DATA` (RFC 9114 §7.2.1).
    public static let data = Self(rawValue: 0x00)
    /// `HEADERS` (RFC 9114 §7.2.2).
    public static let headers = Self(rawValue: 0x01)
    /// `CANCEL_PUSH` (RFC 9114 §7.2.3).
    public static let cancelPush = Self(rawValue: 0x03)
    /// `SETTINGS` (RFC 9114 §7.2.4).
    public static let settings = Self(rawValue: 0x04)
    /// `PUSH_PROMISE` (RFC 9114 §7.2.5).
    public static let pushPromise = Self(rawValue: 0x05)
    /// `GOAWAY` (RFC 9114 §7.2.6).
    public static let goAway = Self(rawValue: 0x07)
    /// `MAX_PUSH_ID` (RFC 9114 §7.2.7).
    public static let maxPushID = Self(rawValue: 0x0D)

    /// Whether this type is a reserved value that maps to an HTTP/2 frame, invalid in HTTP/3.
    ///
    /// The values 0x02 (PRIORITY), 0x06 (PING), 0x08 (WINDOW_UPDATE), and 0x09 (CONTINUATION) are
    /// reserved (RFC 9114 §7.2.1 / §11.2.1); their receipt is a connection error of type
    /// H3_FRAME_UNEXPECTED.
    public var isReservedHTTP2Frame: Bool {
        rawValue == 0x02 || rawValue == 0x06 || rawValue == 0x08 || rawValue == 0x09
    }

    /// Whether this is a reserved "grease" type, `0x1f * N + 0x21` (RFC 9114 §7.2.8), which is ignored.
    public var isGrease: Bool {
        rawValue >= 0x21 && (rawValue - 0x21) % 0x1F == 0
    }
}
