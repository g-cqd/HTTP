//
//  WebSocketFrameEncoder.swift
//  WebSocket
//
//  RFC 6455 §5.2 — serializes a frame to the wire. Server-to-client frames MUST NOT be masked
//  (§5.1), so the encoder emits unmasked frames; the length is written in the minimal 7/16/64-bit
//  form (§5.2). Client masking is added with the client role later.
//

/// Serializes ``WebSocketFrame`` values to the wire, unmasked (RFC 6455 §5.1 / §5.2).
public struct WebSocketFrameEncoder {

    /// Creates a frame encoder.
    public init() {}

    /// Encodes `frame` to its on-the-wire octets (RFC 6455 §5.2), unmasked.
    public func encode(_ frame: WebSocketFrame) -> [UInt8] {
        var out = [UInt8]()
        // 2–10 header octets plus the payload, in a single allocation.
        out.reserveCapacity(10 + frame.payload.count)
        out.append((frame.isFinal ? 0x80 : 0) | frame.opcode.rawValue)
        Self.appendLength(frame.payload.count, into: &out)
        out.append(contentsOf: frame.payload)
        return out
    }

    /// Appends the payload length in the minimal 7/16/64-bit form (RFC 6455 §5.2), MASK bit clear.
    private static func appendLength(_ length: Int, into out: inout [UInt8]) {
        if length <= 125 {
            out.append(UInt8(length))
        } else if length <= 0xFFFF {
            out.append(126)
            out.append(UInt8(truncatingIfNeeded: length >> 8))
            out.append(UInt8(truncatingIfNeeded: length))
        } else {
            out.append(127)
            for shift in stride(from: 56, through: 0, by: -8) {
                out.append(UInt8(truncatingIfNeeded: length >> shift))
            }
        }
    }
}
