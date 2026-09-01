//
//  HTTP3FrameView.swift
//  HTTP3
//
//  RFC 9114 §7.1 — one complete frame seen IN PLACE. `HTTP3FrameDecoder.Frame` owns a fresh `[UInt8]`
//  copy of every payload; this view instead borrows the octets where they already are, in the stream's
//  rolling receive buffer, and hands them to the decoders that already accept a `RawSpan`
//  (`HTTP3Settings.apply` §7.2.4, `QPACKDecoder.decode` RFC 9204 §2.2). Being `~Escapable`, the
//  compiler statically guarantees the view cannot outlive that buffer, so the only copies left are the
//  ones a handler deliberately makes for a value that must escape the borrow — a DATA chunk becoming
//  an event, or a blocked field section held until QPACK unblocks it. Audit CR-F18.
//

/// One complete HTTP/3 frame, borrowed in place from the stream buffer it arrived in (RFC 9114 §7.1).
struct HTTP3FrameView: ~Escapable {
    /// The frame type (RFC 9114 §7.2).
    let type: HTTP3FrameType

    /// The frame payload — `Length` octets, borrowed, never copied.
    let payload: RawSpan

    /// Creates a view of a frame whose payload octets live in the caller's buffer.
    @_lifetime(copy payload)
    init(type: HTTP3FrameType, payload: RawSpan) {
        self.type = type
        self.payload = payload
    }
}
