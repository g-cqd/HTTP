//
//  HTTP2StreamID.swift
//  HTTP2
//
//  RFC 9113 §5.1.1 — stream identifiers. A 31-bit unsigned integer: stream 0 is the connection
//  control stream, client-initiated streams are odd, server-initiated streams are even. The reserved
//  high bit of the wire field is always cleared on construction.
//

/// An HTTP/2 stream identifier (RFC 9113 §5.1.1): a 31-bit value with the reserved bit cleared.
public struct HTTP2StreamID: Sendable, Equatable, Hashable, Comparable, RawRepresentable {
    /// The 31-bit identifier value.
    public let rawValue: UInt32

    /// Creates a stream identifier, masking off the reserved high bit (RFC 9113 §4.1).
    public init(rawValue: UInt32) {
        self.rawValue = rawValue & 0x7FFF_FFFF
    }

    /// Creates a stream identifier from `value` (reserved bit masked).
    public init(_ value: UInt32) {
        self.init(rawValue: value)
    }

    /// The connection control stream, stream 0 (RFC 9113 §5.1.1).
    public static let connection = Self(0)

    /// Whether this is a client-initiated stream — a non-zero odd identifier (RFC 9113 §5.1.1).
    public var isClientInitiated: Bool {
        rawValue != 0 && rawValue.isMultiple(of: 2) == false
    }

    /// Whether this is a server-initiated stream — a non-zero even identifier (RFC 9113 §5.1.1).
    public var isServerInitiated: Bool {
        rawValue != 0 && rawValue.isMultiple(of: 2)
    }

    /// Orders stream identifiers by their numeric value.
    public static func < (lhs: Self, rhs: Self) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}
