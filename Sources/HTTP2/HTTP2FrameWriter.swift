//
//  HTTP2FrameWriter.swift
//  HTTP2
//
//  RFC 9113 §4.1 — the outbound side of the connection engine: a growable buffer of queued frames and
//  the small encoders that append to it. Factored out of `HTTP2Connection` so the engine stays focused
//  on protocol state, not byte layout. The drain hands the buffer to the I/O layer with a swap, never
//  a copy-on-write copy.
//

/// Buffers and serializes outbound HTTP/2 frames for the connection engine (RFC 9113 §4.1).
struct HTTP2FrameWriter {

    private var output = [UInt8]()

    /// Hands the queued octets to the caller and leaves the buffer empty — a swap, not a CoW copy.
    mutating func drain() -> [UInt8] {
        var drained = [UInt8]()
        swap(&drained, &output)
        return drained
    }

    /// Appends a complete frame (header + payload) to the queue (RFC 9113 §4.1).
    mutating func writeFrame(
        _ type: HTTP2FrameType,
        flags: HTTP2FrameFlags = [],
        streamID: HTTP2StreamID = .connection,
        payload: [UInt8] = []
    ) {
        HTTP2FrameHeader(payloadLength: payload.count, type: type, flags: flags, streamID: streamID)
            .encode(into: &output)
        output.append(contentsOf: payload)
    }

    /// Appends a DATA frame whose payload is a slice of a larger buffer (no intermediate `Array`).
    mutating func writeData(
        streamID: HTTP2StreamID,
        endStream: Bool,
        _ payload: ArraySlice<UInt8>
    ) {
        HTTP2FrameHeader(
            payloadLength: payload.count, type: .data, flags: endStream ? [.endStream] : [],
            streamID: streamID
        ).encode(into: &output)
        output.append(contentsOf: payload)
    }

    /// Queues a GOAWAY naming the last processed stream and the error code (RFC 9113 §6.8).
    mutating func writeGoAway(lastStreamID: HTTP2StreamID, code: HTTP2ErrorCode) {
        HTTP2FrameHeader(payloadLength: 8, type: .goAway, streamID: .connection)
            .encode(into: &output)
        appendBigEndian(lastStreamID.rawValue & 0x7FFF_FFFF)
        appendBigEndian(code.rawValue)
    }

    /// Queues a WINDOW_UPDATE for `streamID` (or stream 0) carrying `increment` octets (RFC 9113 §6.9).
    mutating func writeWindowUpdate(_ streamID: HTTP2StreamID, increment: Int) {
        HTTP2FrameHeader(payloadLength: 4, type: .windowUpdate, streamID: streamID)
            .encode(into: &output)
        appendBigEndian(UInt32(increment) & 0x7FFF_FFFF)
    }

    /// Queues an RST_STREAM carrying `code` for `streamID` (RFC 9113 §6.4).
    mutating func writeRstStream(_ streamID: HTTP2StreamID, code: HTTP2ErrorCode) {
        HTTP2FrameHeader(payloadLength: 4, type: .rstStream, streamID: streamID)
            .encode(into: &output)
        appendBigEndian(code.rawValue)
    }

    /// Appends the four big-endian octets of `value` straight into the queue — no throwaway `[UInt8]`
    /// (RFC 9113 uses network byte order throughout).
    private mutating func appendBigEndian(_ value: UInt32) {
        output.append(UInt8((value >> 24) & 0xFF))
        output.append(UInt8((value >> 16) & 0xFF))
        output.append(UInt8((value >> 8) & 0xFF))
        output.append(UInt8(value & 0xFF))
    }
}
