//
//  HTTP2Connection+Connect.swift
//  HTTP2
//
//  RFC 8441 — the Extended CONNECT tunnel half of the connection engine (the WebSocket-over-HTTP/2
//  bootstrap of RFC 9220). After ``HTTP2Connection/Event/extendedConnect(streamID:request:protocol:)``
//  the driver accepts with `acceptTunnel` (a `200` with no END_STREAM, §5), then exchanges opaque
//  bytes with `sendTunnelData` / the `tunnelData` event, and ends the stream with `closeTunnel`.
//

internal import HPACK
internal import HTTPCore

extension HTTP2Connection {

    /// Accepts an Extended CONNECT tunnel on `streamID` (RFC 8441 §5): a `200` response with no
    /// END_STREAM, leaving the stream open as a bidirectional byte tunnel.
    public mutating func acceptTunnel(_ streamID: HTTP2StreamID) throws(HTTP2Error) {
        guard var record = streams[streamID], record.isTunnel else {
            throw .connection(.internalError, "acceptTunnel for a non-tunnel stream")
        }
        try record.stream.sendHeaders(endStream: false)
        let block = encoder.encode([HPACKField(name: ":status", value: "200")])
        writer.writeFrame(.headers, flags: .endHeaders, streamID: streamID, payload: block)
        streams[streamID] = record
    }

    /// Queues `bytes` as DATA on a tunnel stream (RFC 8441 §5), flow-controlled like any body and
    /// deferred past the send window until a WINDOW_UPDATE opens it (RFC 9113 §6.9).
    public mutating func sendTunnelData(_ streamID: HTTP2StreamID, _ bytes: [UInt8]) {
        guard var record = streams.removeValue(forKey: streamID), record.isTunnel else {
            return
        }
        record.pending.append(contentsOf: bytes)
        flushStream(streamID, &record)
    }

    /// Ends a tunnel stream with END_STREAM after flushing any queued DATA (RFC 8441 §5).
    public mutating func closeTunnel(_ streamID: HTTP2StreamID) throws(HTTP2Error) {
        guard var record = streams.removeValue(forKey: streamID) else { return }
        try record.stream.sendData(endStream: true)
        record.pendingEndStream = true
        guard record.pendingOffset >= record.pending.count else {
            flushStream(streamID, &record)  // END_STREAM rides the last queued DATA frame
            return
        }
        // Nothing queued: an empty DATA frame carries END_STREAM to end the tunnel.
        writer.writeData(streamID: streamID, endStream: true, [UInt8]()[...])
        streams[streamID] = record.stream.state == .closed ? nil : record
    }
}
