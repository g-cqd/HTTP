//
//  HTTP2FrameHeader.swift
//  HTTP2
//
//  RFC 9113 §4.1 — the fixed 9-octet frame header that prefixes every HTTP/2 frame:
//
//    +-----------------------------------------------+
//    |                 Length (24)                   |
//    +---------------+---------------+---------------+
//    |   Type (8)    |   Flags (8)   |
//    +-+-------------+---------------+-------------------------------+
//    |R|                 Stream Identifier (31)                      |
//    +=+=============================================================+
//
//  Parsing is zero-copy over a `ByteReader`; the reserved `R` bit is ignored on receipt (§4.1).
//

public import HTTPCore

/// The fixed 9-octet HTTP/2 frame header (RFC 9113 §4.1).
public struct HTTP2FrameHeader: Sendable, Equatable {

    /// The size of the encoded header in octets (RFC 9113 §4.1).
    public static let encodedLength = 9

    /// The frame payload length in octets — the 24-bit `Length` field (not counting this header).
    public var payloadLength: Int

    /// The frame type (RFC 9113 §6).
    public var type: HTTP2FrameType

    /// The type-specific flags (RFC 9113 §4.1).
    public var flags: HTTP2FrameFlags

    /// The stream this frame belongs to, or stream 0 for connection-level frames (RFC 9113 §5.1.1).
    public var streamID: HTTP2StreamID

    /// Creates a frame header.
    public init(
        payloadLength: Int,
        type: HTTP2FrameType,
        flags: HTTP2FrameFlags = [],
        streamID: HTTP2StreamID
    ) {
        self.payloadLength = payloadLength
        self.type = type
        self.flags = flags
        self.streamID = streamID
    }

    /// Parses a 9-octet header from `reader`, or returns `nil` if fewer than 9 octets remain.
    ///
    /// The reserved high bit of the stream identifier is masked off, as a receiver MUST ignore it
    /// (RFC 9113 §4.1).
    public static func parse(_ reader: inout ByteReader) -> HTTP2FrameHeader? {
        guard reader.remaining >= encodedLength else { return nil }
        let start = reader.position
        reader.advance(by: encodedLength)
        let octets = reader.slice(in: start..<(start + encodedLength))

        let payloadLength =
            Int(octets.unsafeLoad(fromByteOffset: 0, as: UInt8.self)) << 16
            | Int(octets.unsafeLoad(fromByteOffset: 1, as: UInt8.self)) << 8
            | Int(octets.unsafeLoad(fromByteOffset: 2, as: UInt8.self))
        let streamRaw =
            UInt32(octets.unsafeLoad(fromByteOffset: 5, as: UInt8.self)) << 24
            | UInt32(octets.unsafeLoad(fromByteOffset: 6, as: UInt8.self)) << 16
            | UInt32(octets.unsafeLoad(fromByteOffset: 7, as: UInt8.self)) << 8
            | UInt32(octets.unsafeLoad(fromByteOffset: 8, as: UInt8.self))
        return HTTP2FrameHeader(
            payloadLength: payloadLength,
            type: HTTP2FrameType(rawValue: octets.unsafeLoad(fromByteOffset: 3, as: UInt8.self)),
            flags: HTTP2FrameFlags(rawValue: octets.unsafeLoad(fromByteOffset: 4, as: UInt8.self)),
            streamID: HTTP2StreamID(rawValue: streamRaw))
    }

    /// Appends the 9-octet header to `output` (RFC 9113 §4.1).
    ///
    /// The reserved `R` bit is always sent as 0.
    public func encode(into output: inout [UInt8]) {
        output.append(UInt8((payloadLength >> 16) & 0xFF))
        output.append(UInt8((payloadLength >> 8) & 0xFF))
        output.append(UInt8(payloadLength & 0xFF))
        output.append(type.rawValue)
        output.append(flags.rawValue)
        output.append(UInt8((streamID.rawValue >> 24) & 0xFF))
        output.append(UInt8((streamID.rawValue >> 16) & 0xFF))
        output.append(UInt8((streamID.rawValue >> 8) & 0xFF))
        output.append(UInt8(streamID.rawValue & 0xFF))
    }
}
