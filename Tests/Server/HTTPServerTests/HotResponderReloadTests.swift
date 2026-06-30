//
//  HotResponderReloadTests.swift
//  HTTPServerTests
//
//  G4a — `HTTPServer.reloadResponder` swaps the responder with no restart. Each request reads the
//  responder once at dispatch, so a request already in flight finishes on the table it read while
//  every request dispatched after the swap uses the new one. Driven over in-memory FakeConnections,
//  with an `AsyncGate` holding one request in flight across the swap so the old/new split is observed
//  deterministically — no real-time races.
//

import HTTPCore
import HTTPTestSupport
import HTTPTransport
import Testing

@testable import HTTPServer

@Suite("HTTPServer — hot responder reload (G4a)")
struct HotResponderReloadTests {
    /// A responder tagged with `label`; optionally records its entry and parks on a gate (to hold a
    /// request in flight) before replying with its label as the body.
    private struct GatedResponder: HTTPResponder {
        let label: String
        var gate: AsyncGate? = nil
        var entered: AsyncEventProbe<String>? = nil

        func respond(
            to _: HTTPRequest, body _: RequestBody, context _: RequestContext
        ) async -> ServerResponse {
            entered?.record(label)
            if let gate { try? await gate.waitUntilOpen() }
            return ServerResponse(HTTPResponse(status: .ok), body: Array(label.utf8))
        }
    }

    /// A `Connection: close` GET so each `FakeConnection` serves exactly one exchange.
    private static func request(_ path: String) -> [UInt8] {
        Array("GET \(path) HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".utf8)
    }

    private func responseBody(of connection: FakeConnection) async -> String {
        String(decoding: await connection.sentBytes(), as: Unicode.UTF8.self)
    }

    @Test("requests dispatched after reloadResponder are served by the new responder")
    func swapRoutesSubsequentRequests() async {
        let server = HTTPServer(
            transport: FakeTransport(), responder: GatedResponder(label: "A")
        )
        let before = FakeConnection(id: TransportConnectionID(1), inbound: Self.request("/x"))
        await server.serve(before)
        let beforeWire = await responseBody(of: before)
        #expect(beforeWire.hasSuffix("\r\n\r\nA"))

        server.reloadResponder(GatedResponder(label: "B"))
        let after = FakeConnection(id: TransportConnectionID(2), inbound: Self.request("/y"))
        await server.serve(after)
        let afterWire = await responseBody(of: after)
        #expect(afterWire.hasSuffix("\r\n\r\nB"))
    }

    @Test("mid-run swap: new requests use the new responder; an in-flight one finishes on the old")
    func inFlightRequestFinishesOnOldResponder() async throws {
        let gate = AsyncGate()
        let entered = AsyncEventProbe<String>()
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: GatedResponder(label: "A", gate: gate, entered: entered)
        )

        // Connection 1: a request that blocks inside the OLD responder (A), parked on the gate.
        let inFlight = FakeConnection(id: TransportConnectionID(1), inbound: Self.request("/a"))
        let serveInFlight = Task { await server.serve(inFlight) }
        _ = try await entered.wait(forAtLeast: 1)  // A is now executing — the request is in flight

        // Swap the table while that request is parked in the old responder.
        server.reloadResponder(GatedResponder(label: "B"))

        // Connection 2: dispatched entirely after the swap → must be served by the NEW responder (B).
        let fresh = FakeConnection(id: TransportConnectionID(2), inbound: Self.request("/b"))
        await server.serve(fresh)
        let freshWire = await responseBody(of: fresh)
        #expect(freshWire.hasSuffix("\r\n\r\nB"))

        // Release the in-flight request: it must complete on the OLD responder (A), not the new one.
        gate.open()
        await serveInFlight.value
        let inFlightWire = await responseBody(of: inFlight)
        #expect(inFlightWire.hasSuffix("\r\n\r\nA"))
    }
}
