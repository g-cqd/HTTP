//
//  HTTP2Connection+ReceiveWindows.swift
//  HTTP2
//
//  RFC 9113 §6.9 — the consumption-gating half of receive flow control, as the driver sees it (audit
//  F2/F4, ADR 0006).
//
//  On a gated stream — an RFC 8441 tunnel or a Phase 1.4 streaming route — `receiveData` debits the
//  windows without crediting anything back, so the peer may only ever be one window ahead of the
//  application. The driver closes that loop from here: it reports how many octets the *handler* has
//  actually taken (``replenishReceiveWindow(_:consumed:)``), hands a retiring stream's unconsumed
//  credit back to the shared connection window (``releaseReceiveWindow(of:)``), and can read the
//  outstanding totals to police a handler that has stopped consuming.
//
//  The engine stays sans-I/O and single-owner: nothing here blocks, and the driver is expected to call
//  it only from whichever task owns the connection engine.
//

extension HTTP2Connection {
    /// Credits both receive windows for body octets the handler has consumed on `streamID`.
    ///
    /// The replenishment half of consumption gating: a stream-level and connection-level WINDOW_UPDATE
    /// are emitted once half of each window has accrued (RFC 9113 §6.9), so the peer is allowed to send
    /// exactly as much more as the application has taken — never more. A report for an unknown stream,
    /// or one larger than the stream actually owes, is clamped rather than trusted; a driver cannot
    /// manufacture window by over-reporting.
    ///
    /// The stream window is not credited once the peer has half-closed the stream (END_STREAM received)
    /// — no further DATA can arrive on it — but the connection window still is.
    public mutating func replenishReceiveWindow(_ streamID: HTTP2StreamID, consumed: Int) {
        guard consumed > 0, var record = streams.removeValue(forKey: streamID) else {
            return
        }
        creditReceiveWindows(
            streamID,
            &record,
            by: consumed,
            endStream: record.stream.state == .halfClosedRemote || record.stream.state == .closed
        )
        streams[streamID] = record
    }

    /// Returns a retired stream's outstanding credit to the CONNECTION window only.
    ///
    /// The connection receive window is shared and outlives every stream (RFC 9113 §6.9.1), so a stream
    /// that is abandoned mid-upload — reset by the peer, swept as stalled, or whose handler simply
    /// finished without draining — must give back what it was holding or the connection permanently
    /// loses that much headroom for every future stream. The stream's own window is deliberately *not*
    /// credited: the stream is going away, and a WINDOW_UPDATE on it would be pointless (and, once the
    /// engine has dropped the record, a §6.9 no-op the peer must ignore anyway).
    ///
    /// Idempotent — the second call finds nothing outstanding.
    public mutating func releaseReceiveWindow(of streamID: HTTP2StreamID) {
        guard var record = streams.removeValue(forKey: streamID) else {
            return
        }
        creditConnectionReceiveWindow(by: record.receiveOutstanding)
        record.receiveOutstanding = 0
        streams[streamID] = record
    }

    /// Octets `streamID` has received but not yet reported as consumed — its unconsumed application
    /// bytes, bounded by ``HTTPLimits/streamReceiveWindow``.
    ///
    /// Zero for a buffered stream (it credits at arrival) and for an unknown one.
    public func outstandingReceiveCredit(of streamID: HTTP2StreamID) -> Int {
        streams[streamID]?.receiveOutstanding ?? 0
    }

    /// Octets this connection has received but not yet reported as consumed, across every stream.
    ///
    /// The hard memory bound consumption gating buys: never more than
    /// ``HTTPLimits/connectionReceiveWindow``, whatever the stream count, route body limit, or handler
    /// behavior — the peer cannot send past a window it has not been given back.
    public var outstandingReceiveCredit: Int { connectionReceiveOutstanding }

    /// Whether the engine still tracks `streamID`.
    ///
    /// A driver dispatches handlers off the connection task, so a response can be produced for a stream
    /// the peer has since reset (RFC 9113 §6.4). Applying it would be an `internalError` — a
    /// *connection*-level fault that would take every sibling stream down with it — so the driver
    /// checks this first and drops the late response instead (audit F6).
    public func isStreamOpen(_ streamID: HTTP2StreamID) -> Bool { streams[streamID] != nil }
}
