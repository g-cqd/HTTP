//
//  HTTP3Connection+Connect.swift
//  HTTP3
//
//  RFC 9220 — the Extended CONNECT tunnel half of the HTTP/3 connection engine (WebSocket over HTTP/3,
//  the h3 analog of RFC 8441 over HTTP/2). After ``HTTP3Connection/Event/extendedConnect(streamID:request:protocol:)``
//  the driver accepts with `acceptTunnel` (a `200` HEADERS frame with no FIN, leaving the request stream
//  open) and then exchanges opaque bytes — carried in HTTP/3 DATA frames on that stream — via
//  `sendTunnelData` and the `tunnelData` event, ending the tunnel with `closeTunnel` (FIN).
//
//  The engine keeps no per-tunnel byte state: like the native streaming response path, the accept HEADERS
//  and each DATA frame are returned to the driver to send directly on the (independent, transport-flow-
//  controlled) QUIC stream (RFC 9000 §2), so there is no action-drain and the QPACK encoder stays static.
//

public import HTTPCore

extension HTTP3Connection {
    /// Accepts an Extended CONNECT tunnel on `streamID` (RFC 9220 / RFC 8441 §5): returns a QPACK-encoded
    /// `200` HEADERS frame with **no FIN**, leaving the request stream open as a bidirectional byte tunnel.
    ///
    /// When `secWebSocketExtensions` is supplied it is echoed on the `200` — the WebSocket-over-HTTP/3
    /// permessage-deflate acceptance (RFC 7692 §5.1 over RFC 9220). The driver sends the returned bytes
    /// with `fin:false`; tunnel bytes then flow via ``sendTunnelData(_:_:)`` and the `tunnelData` event.
    /// Throws `H3_INTERNAL_ERROR` for an unknown or non-tunnel stream. The field section is static (no
    /// dynamic-table inserts), matching the no-action-drain streaming model.
    public func acceptTunnel(
        _ streamID: QUICStreamID,
        secWebSocketExtensions: String? = nil
    ) throws(HTTP3Error) -> [UInt8] {
        guard streams[streamID]?.isTunnel == true else {
            throw .connection(.h3InternalError, "acceptTunnel for a non-tunnel stream")
        }
        var response = HTTPResponse(status: .ok)
        if let secWebSocketExtensions {
            response.headerFields.append(secWebSocketExtensions, for: .secWebSocketExtensions)
        }
        return HTTP3FrameWriter.frame(.headers, payload: encodeResponseSection(response))
    }

    /// Frames `bytes` as a tunnel DATA frame (RFC 9220 / RFC 8441 §5) for the driver to send on the
    /// stream; empty for an unknown / non-tunnel stream (a defensive no-op).
    public func sendTunnelData(_ streamID: QUICStreamID, _ bytes: [UInt8]) -> [UInt8] {
        guard streams[streamID]?.isTunnel == true else {
            return []
        }
        return Self.dataFrame(bytes)
    }

    /// Ends a tunnel stream (RFC 9220 / RFC 8441 §5): untracks it so the FIN the driver sends closes the
    /// tunnel.
    ///
    /// Idempotent — a no-op once the peer's FIN already surfaced `tunnelClosed`.
    public mutating func closeTunnel(_ streamID: QUICStreamID) {
        streams[streamID] = nil
    }
}
