//
//  HTTP2TunnelSignal.swift
//  HTTPServer
//
//  A signal fed into one tunnel's mailbox (consumer → that tunnel's dedicated pump task).
//

/// A signal fed into one tunnel's mailbox (consumer → that tunnel's dedicated pump task).
enum HTTP2TunnelSignal: Sendable {
    /// A decoded tunnel DATA chunk (RFC 8441 §5) for this stream, in wire order.
    case bytes([UInt8])
    /// The peer ended this tunnel (`.tunnelClosed` END_STREAM, or `.streamReset`) — the pump should fire
    /// its `onClose` lifecycle hook and stop; the consumer has already removed this tunnel from its own
    /// bookkeeping and needs no further wakeup back.
    case peerEnded
}
