//
//  HTTP2FrameView.swift
//  HTTP2
//
//  RFC 9113 §4.1 — one complete frame seen IN PLACE. `HTTP2FrameDecoder.Frame` owns a fresh `[UInt8]`
//  copy of every payload; this view instead borrows the octets where they already are, in the
//  connection's rolling inbound buffer, and hands them to the decoders that already accept a `RawSpan`
//  (`HTTP2Settings.apply` §6.5, `HPACKDecoder.decode` §4.3). Being `~Escapable`, the compiler
//  statically guarantees the view cannot outlive that buffer, so the only copies left are the ones a
//  handler deliberately makes for a value that must escape the borrow — a DATA chunk becoming an event
//  (§6.1). Audit CR-F18.
//

/// One complete HTTP/2 frame, borrowed in place from the buffer it arrived in (RFC 9113 §4.1).
struct HTTP2FrameView: ~Escapable {
    /// The frame header (RFC 9113 §4.1).
    let header: HTTP2FrameHeader

    /// The frame payload — `header.payloadLength` octets, borrowed, never copied.
    let payload: RawSpan

    /// Creates a view of a frame whose payload octets live in the caller's buffer.
    @_lifetime(copy payload)
    init(header: HTTP2FrameHeader, payload: RawSpan) {
        self.header = header
        self.payload = payload
    }
}
