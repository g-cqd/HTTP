//
//  HTTPServerShutdownTests.swift
//  HTTPServerTests
//
//  Graceful shutdown (RFC 9110 §7.6.1 / RFC 9113 §6.8): once shutdown() begins, an in-flight
//  connection finishes its current exchange and closes — HTTP/1 answers with Connection: close and
//  does not serve a following pipelined request.
//

import HTTPCore
import HTTPTestSupport
import HTTPTransport
import Testing

@testable import HTTPServer

@Suite("HTTPServer — graceful shutdown")
struct HTTPServerShutdownTests {
    @Test("a draining server answers HTTP/1 with Connection: close and stops after the exchange")
    func http1DrainsWithConnectionClose() async {
        // The responder echoes the path so the served request is identifiable on the wire.
        let responder = ClosureResponder { request, _, _ in
            ServerResponse(HTTPResponse(status: .ok), body: Array(request.path.utf8))
        }
        // Two pipelined requests: draining must answer the first and not serve the second.
        let pipelined = "GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n"
        let bytes = Array(pipelined.utf8)
        let connection = FakeConnection(id: TransportConnectionID(1), inbound: bytes)
        let server = HTTPServer(transport: FakeTransport(), responder: responder)
        await server.shutdown()  // begin draining before this connection is served
        await server.serve(connection)
        let wire = String(decoding: await connection.sentBytes(), as: Unicode.UTF8.self)
        #expect(wire.lowercased().contains("connection: close"))
        #expect(wire.contains("/a"))  // first request served
        #expect(!wire.contains("/b"))  // second pipelined request not served during drain
    }

    @Test("shutdown is idempotent")
    func shutdownIsIdempotent() async {
        let responder = ClosureResponder { _, _, _ in ServerResponse(HTTPResponse(status: .ok)) }
        let server = HTTPServer(transport: FakeTransport(), responder: responder)
        await server.shutdown()
        await server.shutdown()  // a second call must not trap or re-shut-down the transport
    }

    @Test(
        "shutdown force-closes a connection still in flight past the deadline",
        .timeLimit(.minutes(1)))
    func forceClosesStragglerPastDeadline() async {
        let clock = TestClock()
        // Keep the idle watchdog far out, so the force-close — not a keep-alive timeout — closes it.
        let limits = HTTPLimits(
            headerReadTimeout: .seconds(3_600),
            idleTimeout: .seconds(3_600),
            keepAliveTimeout: .seconds(3_600)
        )
        let probe = AsyncEventProbe<TransportConnectionID>()
        let responder = ClosureResponder { _, _, _ in ServerResponse(HTTPResponse(status: .ok)) }
        let hanging = HangingConnection(id: TransportConnectionID(1), admissionProbe: probe)
        let server = HTTPServer(
            transport: FakeTransport(), responder: responder, limits: limits, clock: clock
        )
        await withTaskGroup(of: Void.self) { group in
            group.addTask { await server.serve(hanging) }  // registers, then blocks on receive
            _ = try? await probe.wait(forAtLeast: 1)  // the connection is registered + being served
            group.addTask { await server.shutdown(within: .seconds(1)) }
            group.addTask {
                while !Task.isCancelled {
                    try? await clock.waitForSleepers(atLeast: 1)
                    clock.advance(by: .milliseconds(100))
                }
            }
            await group.next()  // shutdown() returns once it has force-closed the straggler
            group.cancelAll()  // unblock the hanging serve + stop the pump
        }
        #expect(await hanging.isClosed())
    }
}
