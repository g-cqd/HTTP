//
//  HTTP2FrameDecoder.swift
//  HTTP2
//
//  RFC 9113 §4.1 / §4.2 — the incremental frame decoder. It pulls one complete frame (header plus the
//  full payload) from an accumulating buffer, returning nil while a frame is still arriving so the
//  caller can read more. A payload larger than the advertised SETTINGS_MAX_FRAME_SIZE is a
//  FRAME_SIZE_ERROR (§4.2). Iterative; no recursion.
//

public import HTTPCore

/// Pulls complete HTTP/2 frames from an accumulating byte buffer (RFC 9113 §4).
public struct HTTP2FrameDecoder {
    /// One fully received frame: its header and the payload octets.
    public struct Frame: Sendable, Equatable {
        /// The frame header (RFC 9113 §4.1).
        public let header: HTTP2FrameHeader

        /// The frame payload (`header.payloadLength` octets).
        public let payload: [UInt8]

        /// Creates a frame from a header and its payload.
        public init(header: HTTP2FrameHeader, payload: [UInt8]) {
            self.header = header
            self.payload = payload
        }
    }

    /// The largest payload accepted, our advertised SETTINGS_MAX_FRAME_SIZE (RFC 9113 §4.2).
    private let maxFrameSize: Int

    /// Creates a decoder that rejects payloads larger than `maxFrameSize` (default 16,384).
    public init(maxFrameSize: Int = 16_384) {
        self.maxFrameSize = maxFrameSize
    }

    /// Pulls the next complete frame from `reader`, advancing it; returns nil if one is still arriving.
    ///
    /// Throws FRAME_SIZE_ERROR if the header declares a payload larger than `maxFrameSize` (§4.2).
    public func nextFrame(_ reader: inout ByteReader) throws(HTTP2Error) -> Frame? {
        // Probe on a copy so an incomplete frame leaves the real cursor untouched for a later retry.
        var probe = reader
        guard let header = HTTP2FrameHeader.parse(&probe) else {
            return nil
        }
        guard header.payloadLength <= maxFrameSize else {
            throw .connection(.frameSizeError, "frame payload exceeds SETTINGS_MAX_FRAME_SIZE")
        }
        guard probe.remaining >= header.payloadLength else {
            return nil
        }

        reader.advance(by: HTTP2FrameHeader.encodedLength)
        let start = reader.position
        reader.advance(by: header.payloadLength)
        let payload = reader.slice(in: start ..< (start + header.payloadLength))
            .withUnsafeBytes { Array($0) }
        return Frame(header: header, payload: payload)
    }
}
