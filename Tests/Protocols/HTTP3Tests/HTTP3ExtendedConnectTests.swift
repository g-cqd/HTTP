//
//  HTTP3ExtendedConnectTests.swift
//  HTTP3Tests
//
//  RFC 9220 — Extended CONNECT over HTTP/3 (WebSocket over h3): a CONNECT carrying `:protocol` surfaces a
//  tunnel event when ENABLE_CONNECT_PROTOCOL is advertised (else H3_MESSAGE_ERROR), `acceptTunnel` emits a
//  `200` HEADERS frame with no FIN, and opaque bytes round-trip in HTTP/3 DATA frames in both directions
//  until the peer's FIN surfaces `tunnelClosed` — the h3 analog of the RFC 8441 tunnel.
//

import HTTPCore
import Testing

@testable import HTTP3

@Suite("RFC 9220 — Extended CONNECT over HTTP/3")
struct HTTP3ExtendedConnectTests: HTTP3WireFixtures {
    private static let stream = QUICStreamID(0)  // client-initiated bidirectional request stream

    /// The Extended CONNECT field section: `:method=CONNECT` + `:protocol`, with `:scheme`/`:path`/
    /// `:authority` present (RFC 8441 §4, unlike a classic CONNECT).
    private func extendedConnectSection(protocol proto: String = "websocket") -> [UInt8] {
        fieldSection([
            HeaderField(name: ":method", value: "CONNECT"),
            HeaderField(name: ":protocol", value: proto),
            HeaderField(name: ":scheme", value: "https"),
            HeaderField(name: ":authority", value: "example.com"),
            HeaderField(name: ":path", value: "/chat")
        ])
    }

    /// A connection advertising ENABLE_CONNECT_PROTOCOL (RFC 9220 §3).
    private func tunnelConnection() -> HTTP3Connection {
        var settings = HTTP3Settings()
        settings.enableConnectProtocol = true
        return HTTP3Connection(localSettings: settings)
    }

    @Test("an Extended CONNECT surfaces a tunnel event without awaiting FIN (RFC 9220 §3)")
    func surfacesTunnel() throws {
        var connection = tunnelConnection()
        let events = try connection.receive(
            Self.stream, frame(.headers, extendedConnectSection()), fin: false
        )
        guard case .extendedConnect(let id, let request, let proto) = events.first else {
            Issue.record("expected an extendedConnect event")
            return
        }
        #expect(id == Self.stream)
        #expect(request.method == .connect)
        #expect(proto == "websocket")
    }

    @Test("Extended CONNECT without ENABLE_CONNECT_PROTOCOL is H3_MESSAGE_ERROR (RFC 9220 §3)")
    func rejectedWhenDisabled() throws {
        var connection = HTTP3Connection()  // enableConnectProtocol defaults to false
        let events = try connection.receive(
            Self.stream, frame(.headers, extendedConnectSection()), fin: false
        )
        #expect(events.isEmpty)  // refused as a stream error; the connection survives
        #expect(resetStreamCode(&connection) == HTTP3ErrorCode.h3MessageError.rawValue)
    }

    @Test("acceptTunnel emits a 200 HEADERS frame, echoing permessage-deflate (RFC 7692 §5.1)")
    func acceptEmits200() throws {
        var connection = tunnelConnection()
        _ = try connection.receive(
            Self.stream, frame(.headers, extendedConnectSection()), fin: false
        )
        let accept = try connection.acceptTunnel(
            Self.stream, secWebSocketExtensions: "permessage-deflate"
        )
        let response = try decodeResponse(accept)
        #expect(response.status == "200")
        #expect(response.body.isEmpty)  // a HEADERS frame only — the driver sends it fin:false
    }

    @Test("opaque bytes round-trip as DATA frames in both directions (RFC 9220 §3)")
    func tunnelDataRoundTrip() throws {
        var connection = tunnelConnection()
        _ = try connection.receive(
            Self.stream, frame(.headers, extendedConnectSection()), fin: false
        )
        _ = try connection.acceptTunnel(Self.stream)

        // Inbound: a client DATA frame on the tunnel surfaces opaque bytes, not a request body.
        let inbound = try connection.receive(
            Self.stream, frame(.data, Array("client-bytes".utf8)), fin: false
        )
        guard case .tunnelData(let id, let bytes) = inbound.first else {
            Issue.record("expected a tunnelData event")
            return
        }
        #expect(id == Self.stream)
        #expect(bytes == Array("client-bytes".utf8))

        // Outbound: a server tunnel write frames as a DATA frame carrying exactly those bytes.
        let outbound = connection.sendTunnelData(Self.stream, Array("server-bytes".utf8))
        #expect(outbound == HTTP3Connection.dataFrame(Array("server-bytes".utf8)))
    }

    @Test("the peer ending a tunnel surfaces tunnelClosed (RFC 9220 §3)")
    func tunnelClosedOnFin() throws {
        var connection = tunnelConnection()
        _ = try connection.receive(
            Self.stream, frame(.headers, extendedConnectSection()), fin: false
        )
        _ = try connection.acceptTunnel(Self.stream)
        let events = try connection.receive(Self.stream, [], fin: true)
        #expect(events.contains(.tunnelClosed(streamID: Self.stream)))
    }
}
