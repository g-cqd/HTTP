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
    public struct Frame: Sendable, Equatable, HTTPFrame {
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

    /// The largest payload accepted on any frame that is not DATA, in octets.
    ///
    /// The control plane: a field section (HEADERS / PUSH_PROMISE), SETTINGS, GOAWAY, and every
    /// unknown or reserved type whose payload still has to be skipped (RFC 9114 §7.2.8). These carry
    /// bookkeeping, not content, so a large one is abuse rather than traffic.
    private let maxFrameSize: Int

    /// The largest DATA payload accepted, in octets.
    ///
    /// Separate because RFC 9114 gives the two different meanings. `SETTINGS_MAX_FIELD_SECTION_SIZE`
    /// (§4.2.2, §7.2.4.1) bounds a *field section*, measured on the uncompressed name + value + 32
    /// sizing — it says nothing about DATA, which §7.2.1 defines as "arbitrary, variable-length
    /// sequences of bytes associated with HTTP request or response content" and gives no ceiling at
    /// all. HTTP/3 has no analogue of HTTP/2's `SETTINGS_MAX_FRAME_SIZE` (§7.1); QUIC flow control
    /// (RFC 9000 §4) is what bounds inbound data on the wire, so any per-frame DATA ceiling here is
    /// the implementation's own resource guard and belongs on the *body* budget, not the header one.
    private let maxDataFrameSize: Int

    /// Creates a decoder that rejects a non-DATA payload larger than `maxFrameSize` and a DATA payload
    /// larger than `maxDataFrameSize`.
    ///
    /// `maxDataFrameSize` defaults to `maxFrameSize`, i.e. one ceiling for every type — for callers
    /// (tests, tools) that drive the frame layer without a body budget to speak of.
    public init(maxFrameSize: Int, maxDataFrameSize: Int? = nil) {
        self.maxFrameSize = maxFrameSize
        self.maxDataFrameSize = maxDataFrameSize ?? maxFrameSize
    }

    /// Pulls the next complete frame from `reader`, advancing it; returns nil if one is still arriving.
    ///
    /// Throws `H3_EXCESSIVE_LOAD` if the header declares a payload larger than `maxFrameSize` (a
    /// resource-exhaustion guard, RFC 9114 §7.1 / §8.1).
    /// The OWNING half: it materializes the payload, so the frame outlives the buffer it came from.
    /// The connection engine uses ``nextFrameRange(_:)`` instead and never pays this copy; this entry
    /// point remains for callers that need an escaping value (tests, tools, out-of-module clients).
    public func nextFrame(_ reader: inout ByteReader) throws(HTTP3Error) -> Frame? {
        guard let framing = try nextFrameRange(&reader) else {
            return nil
        }
        let payload = reader.slice(in: framing.payload).withUnsafeBytes { Array($0) }
        return Frame(type: framing.type, payload: payload)
    }

    /// Locates the next complete frame without copying it, as a type plus a payload range.
    ///
    /// The range indexes `reader`'s own buffer.
    ///
    /// The BORROWED half (audit CR-F18), and the implementation ``nextFrame(_:)`` copies from — so the
    /// two cannot disagree about where a frame starts or ends. The cursor advances identically; the
    /// caller reads the payload in place via ``ByteReader/slice(in:)`` and materializes only what has
    /// to outlive the borrow. Returns nil while a frame is still arriving, leaving the cursor put.
    func nextFrameRange(
        _ reader: inout ByteReader
    ) throws(HTTP3Error) -> (type: HTTP3FrameType, payload: Range<Int>)? {
        // Probe on a copy so an incomplete frame leaves the real cursor untouched for a later retry.
        var probe = reader
        guard let rawType = QUICVarint.decode(&probe) else {
            return nil
        }
        guard let length = QUICVarint.decode(&probe) else {
            return nil
        }
        let type = HTTP3FrameType(rawValue: rawType)
        // Per frame TYPE, because the two ceilings mean different things (see `maxDataFrameSize`).
        let bound = type == .data ? maxDataFrameSize : maxFrameSize
        guard length <= UInt64(bound) else {
            throw .connection(.h3ExcessiveLoad, "frame payload exceeds the accepted maximum")
        }
        let payloadLength = Int(length)
        guard probe.remaining >= payloadLength else {
            return nil
        }

        reader.advance(by: probe.position - reader.position)  // consume the type + length varints
        let start = reader.position
        reader.advance(by: payloadLength)
        return (type, start ..< (start + payloadLength))
    }
}
