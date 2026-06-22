//
//  HTTP3FrameDecoder.swift
//  HTTP3
//
//  RFC 9114 §7.1 — the HTTP/3 frame layer. Every frame is a variable-length Type, a variable-length
//  Length, and Length octets of payload. Unlike HTTP/2's single demultiplexed octet stream, QUIC
//  delivers bytes per stream, so this decoder is driven over one stream's accumulating buffer; it pulls
//  one complete frame at a time and returns nil while a frame is still arriving (more bytes needed, or
//  the stream has not yet reached FIN). A payload larger than the configured bound is rejected as
//  excessive load. Iterative; no recursion.
//
//  Note: "a frame whose Length runs past the end of the stream" (RFC 9114 §7.1) is distinguishable from
//  "need more bytes" only when the stream's FIN has been seen — that determination is made by the
//  connection, which knows FIN; here an unfinished frame is simply reported as nil.
//

public import HTTPCore

/// Pulls complete HTTP/3 frames from one stream's accumulating byte buffer (RFC 9114 §7.1).
public struct HTTP3FrameDecoder {

    /// One fully received frame: its type and payload octets.
    public struct Frame: Sendable, Equatable {

        /// The frame type (RFC 9114 §7.2).
        public let type: HTTP3FrameType

        /// The frame payload (`Length` octets).
        public let payload: [UInt8]

        /// Creates a frame from a type and its payload.
        public init(type: HTTP3FrameType, payload: [UInt8]) {
            self.type = type
            self.payload = payload
        }
    }

    /// The largest frame payload accepted, in octets, before failing with excessive load.
    private let maxFrameSize: Int

    /// Creates a decoder that rejects payloads larger than `maxFrameSize`.
    public init(maxFrameSize: Int) {
        self.maxFrameSize = maxFrameSize
    }

    /// Pulls the next complete frame from `reader`, advancing it; returns nil if one is still arriving.
    ///
    /// Throws `H3_EXCESSIVE_LOAD` if the header declares a payload larger than `maxFrameSize` (a
    /// resource-exhaustion guard, RFC 9114 §7.1 / §8.1).
    public func nextFrame(_ reader: inout ByteReader) throws(HTTP3Error) -> Frame? {
        // Probe on a copy so an incomplete frame leaves the real cursor untouched for a later retry.
        var probe = reader
        guard let rawType = QUICVarint.decode(&probe) else { return nil }
        guard let length = QUICVarint.decode(&probe) else { return nil }
        guard length <= UInt64(maxFrameSize) else {
            throw .connection(.h3ExcessiveLoad, "frame payload exceeds the accepted maximum")
        }
        let payloadLength = Int(length)
        guard probe.remaining >= payloadLength else { return nil }

        reader.advance(by: probe.position - reader.position)  // consume the type + length varints
        let start = reader.position
        reader.advance(by: payloadLength)
        let payload = reader.slice(in: start..<(start + payloadLength)).withUnsafeBytes {
            Array($0)
        }
        return Frame(type: HTTP3FrameType(rawValue: rawType), payload: payload)
    }
}
