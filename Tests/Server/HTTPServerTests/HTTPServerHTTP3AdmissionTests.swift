//
//  HTTPServerHTTP3AdmissionTests.swift
//  HTTPServerTests
//
//  Audit addendum P0.5 — an HTTP/3 peer must be charged against the *same* process-wide connection
//  ceiling as an HTTP/1.1 or HTTP/2 one, and a QUIC connection must be reachable by the graceful
//  drain. The QUIC accept loop used to create one serve task per connection with no counts at all,
//  and the shutdown registry held TCP connections only.
//
//  A resource-exhaustion defense in the spirit of RFC 9110 §15.5.30 (429) — CWE-770 / CWE-400 — and
//  the HTTP/3 half of RFC 9114 §5.2 graceful shutdown.
//

import HTTP3
import HTTPCore
import HTTPTestSupport
import HTTPTransport
import Testing

@testable import HTTPServer

@Suite("HTTP/3 — admission and drain cover QUIC (addendum P0.5)")
struct HTTPServerHTTP3AdmissionTests {
    @Test("a QUIC connection over the global ceiling is refused, not served")
    func globalCeilingRefusesQUIC() async throws {
        let transport = FakeQUICTransport()  // ungated: the server must charge
        let server = try Self.makeServer(
            transport,
            limits: Self.limits(total: 1, perHost: 8)
        )
        let running = Task { await server.runHTTP3() }
        defer { running.cancel() }

        let first = FakeQUICConnection()
        let second = FakeQUICConnection()
        transport.accept(first)
        try await settle { server.admission.counts.total == 1 }
        transport.accept(second)

        try await settle { !second.closeCodes.isEmpty }
        #expect(second.closeCodes == [HTTP3ErrorCode.h3ExcessiveLoad.rawValue])
        #expect(first.closeCodes.isEmpty)
        #expect(server.admission.counts.total == 1)  // the refusal charged nothing
    }

    @Test("a QUIC connection over the per-client ceiling is refused")
    func perClientCeilingRefusesQUIC() async throws {
        let transport = FakeQUICTransport()
        let server = try Self.makeServer(
            transport,
            limits: Self.limits(total: 64, perHost: 1)
        )
        let running = Task { await server.runHTTP3() }
        defer { running.cancel() }

        let peer = TransportAddress(host: "198.51.100.9", port: 4_433)
        let first = FakeQUICConnection(peer: peer)
        let second = FakeQUICConnection(peer: peer)
        transport.accept(first)
        try await settle { server.admission.counts.total == 1 }
        transport.accept(second)

        try await settle { !second.closeCodes.isEmpty }
        #expect(second.closeCodes == [HTTP3ErrorCode.h3ExcessiveLoad.rawValue])
        #expect(server.admission.counts.total == 1)
    }

    @Test("a slot the listener already charged is adopted, not charged twice")
    func transportTicketIsAdopted() async throws {
        let transport = FakeQUICTransport(charging: true)
        let server = try Self.makeServer(
            transport,
            limits: Self.limits(total: 4, perHost: 4)
        )
        let running = Task { await server.runHTTP3() }
        defer { running.cancel() }

        transport.accept(FakeQUICConnection())
        try await settle { server.admission.counts.total >= 1 }
        // One connection, one slot — the server adopted the listener's ticket rather than charging
        // a second for the same peer.
        #expect(server.admission.counts.total == 1)
        #expect(transport.refusalCount == 0)
    }

    @Test("the listener refuses at the gate once the ceiling is full, before any serve task")
    func chargingTransportRefusesAtTheGate() async throws {
        let transport = FakeQUICTransport(charging: true)
        let server = try Self.makeServer(
            transport,
            limits: Self.limits(total: 1, perHost: 4)
        )
        let running = Task { await server.runHTTP3() }
        defer { running.cancel() }

        transport.accept(FakeQUICConnection())
        try await settle { server.admission.counts.total == 1 }
        transport.accept(FakeQUICConnection())

        try await settle { transport.refusalCount == 1 }
        #expect(transport.refusalCount == 1)
        #expect(server.admission.counts.total == 1)
    }

    @Test("shutdown sends a GOAWAY on the QUIC control stream and closes the connection")
    func shutdownDrainsQUIC() async throws {
        let transport = FakeQUICTransport()
        let server = try Self.makeServer(transport, limits: Self.limits(total: 8, perHost: 8))
        let running = Task { await server.runHTTP3() }
        defer { running.cancel() }

        let quic = FakeQUICConnection()
        transport.accept(quic)
        // The server's own control + QPACK streams are open once it has three of them (§6.2).
        try await settle { quic.openedStreams.count == 3 }

        await server.shutdown(within: .milliseconds(1))

        // The control stream carries its §6.2.1 preamble, then the GOAWAY frame (type 0x07, §7.2.6).
        let control = quic.openedStreams.first
        #expect(control?.sends.count == 2)
        #expect(control?.sends.last?.first == 0x07)
        #expect(quic.closeCodes.contains(HTTP3ErrorCode.h3NoError.rawValue))
    }

    // MARK: - Fixtures

    private static func makeServer(
        _ transport: any QUICServerTransport,
        limits: HTTPLimits
    ) throws -> HTTPServer<ContinuousClock> {
        HTTPServer(
            transport: try TransportFactory.make(
                TransportConfiguration(port: 0, backbone: .fake)
            ),
            responder: ClosureResponder { _, _, _ in
                ServerResponse(HTTPResponse(status: .ok), body: [])
            },
            quicTransport: transport,
            limits: limits
        )
    }

    private static func limits(total: Int, perHost: Int) -> HTTPLimits {
        HTTPLimits.default.with {
            $0.maxConnections = total
            $0.maxConnectionsPerClient = perHost
        }
    }
}
