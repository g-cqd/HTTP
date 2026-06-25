//
//  QUICStreamID.swift
//  HTTPCore
//
//  RFC 9000 §2.1 — QUIC stream identifiers. A 62-bit unsigned integer whose two least-significant
//  bits classify the stream: bit 0 is the initiator (0 = client, 1 = server) and bit 1 is the
//  directionality (0 = bidirectional, 1 = unidirectional). The high bits are masked on construction.
//  HTTP/3 request streams are client-initiated bidirectional; the control and QPACK streams are
//  unidirectional (RFC 9114 §6).
//

/// A QUIC stream identifier (RFC 9000 §2.1): a 62-bit value with low-2-bit type classification.
public struct QUICStreamID: Sendable, Equatable, Hashable, Comparable, RawRepresentable {
    /// The 62-bit identifier value.
    public let rawValue: UInt64

    /// Creates a stream identifier, masking off the reserved high bits to 62 bits (RFC 9000 §2.1).
    public init(rawValue: UInt64) {
        self.rawValue = rawValue & 0x3FFF_FFFF_FFFF_FFFF
    }

    /// Creates a stream identifier from `value` (high bits masked to 62 bits).
    public init(_ value: UInt64) {
        self.init(rawValue: value)
    }

    /// The four stream classes selected by the two low bits of the identifier (RFC 9000 §2.1).
    public enum Kind: Sendable, Equatable {
        /// Client-initiated bidirectional (low bits `0b00`) — an HTTP/3 request stream (RFC 9114 §6.1).
        case clientBidirectional
        /// Server-initiated bidirectional (low bits `0b01`).
        case serverBidirectional
        /// Client-initiated unidirectional (low bits `0b10`).
        case clientUnidirectional
        /// Server-initiated unidirectional (low bits `0b11`).
        case serverUnidirectional
    }

    /// The stream class, from the two low bits (RFC 9000 §2.1).
    public var kind: Kind {
        switch rawValue & 0x3 {
            case 0x0:
                .clientBidirectional
            case 0x1:
                .serverBidirectional
            case 0x2:
                .clientUnidirectional
            default:
                .serverUnidirectional
        }
    }

    /// Whether the stream was opened by the client — an even initiator bit (RFC 9000 §2.1).
    public var isClientInitiated: Bool { rawValue & 0x1 == 0 }

    /// Whether the stream was opened by the server — an odd initiator bit (RFC 9000 §2.1).
    public var isServerInitiated: Bool { rawValue & 0x1 != 0 }

    /// Whether the stream is unidirectional — the direction bit set (RFC 9000 §2.1).
    public var isUnidirectional: Bool { rawValue & 0x2 != 0 }

    /// Whether the stream is bidirectional — the direction bit clear (RFC 9000 §2.1).
    public var isBidirectional: Bool { rawValue & 0x2 == 0 }

    /// Orders stream identifiers by their numeric value.
    public static func < (lhs: Self, rhs: Self) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}
