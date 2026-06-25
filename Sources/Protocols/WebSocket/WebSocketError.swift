//
//  WebSocketError.swift
//  WebSocket
//
//  RFC 6455 §5 / §7.4 — the framing and connection violations the engine fails closed on, each mapped
//  to the Close status code (§7.4.1) the connection reports before closing.
//

/// A WebSocket framing or connection violation (RFC 6455 §5 / §6), with its Close code (§7.4.1).
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

    /// A frame's payload exceeded the configured maximum — a resource-exhaustion guard.
    case payloadTooLong

    /// A client-to-server frame was not masked (RFC 6455 §5.1).
    case maskingRequired

    /// A CONTINUATION frame arrived with no fragmented message in progress (RFC 6455 §5.4).
    case unexpectedContinuation

    /// A new data frame arrived while a fragmented message was still open (RFC 6455 §5.4).
    case interleavedDataFrame

    /// A reassembled message exceeded the configured maximum — a resource-exhaustion guard.
    case messageTooLarge

    /// A Close frame carried a single payload octet (a code must be 0 or ≥2 octets) (RFC 6455 §5.5.1).
    case malformedClosePayload

    /// A Close frame carried a status code that must not appear on the wire (RFC 6455 §7.4.1).
    case invalidCloseCode

    /// A text message (or Close reason) was not valid UTF-8 (RFC 6455 §8.1).
    case invalidTextEncoding

    /// A permessage-deflate message failed to inflate, or its inflated size exceeded the message cap
    /// (RFC 7692 §7.2.2; the cap is the CWE-409 decompression-bomb defense).
    case invalidCompressedData

    /// The Close status code to report for this violation before closing (RFC 6455 §7.4.1).
    public var closeCode: WebSocketCloseCode {
        switch self {
            case .payloadTooLong, .messageTooLarge:
                .messageTooBig  // 1009
            case .invalidTextEncoding, .invalidCompressedData:
                .invalidPayloadData  // 1007
            default:
                .protocolError  // 1002
        }
    }
}
