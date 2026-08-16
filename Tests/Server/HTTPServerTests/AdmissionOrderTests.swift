//
//  AdmissionOrderTests.swift
//  HTTPServerTests
//
//  The core claim of audit finding 8: **no serve task is created for a connection over the cap**.
//  Admission used to run inside `HTTPServer.accept(_:)` — i.e. after the task group had already
//  created the child task — so the number being bounded was "accepted and task-spawned", not
//  "accepted", and the yielded-connection queue grew unbounded ahead of it. These pin the fixed order:
//  a gated backbone charges the slot at its accept point and never queues a reject, and the server
//  adopts that slot instead of charging a second one.
//
//  Standards: a resource-exhaustion defense in the spirit of RFC 9110 §15.5.30 (429) — CWE-770
//  (allocation of resources without limits), CWE-400 (uncontrolled resource consumption).
//

import HTTPCore
import HTTPTestSupport
import HTTPTransport
import Testing

@testable import HTTPServer

@Suite("Admission order — the cap is charged before the serve task exists (audit F8)")
struct AdmissionOrderTests {
    private static func makeInbound(
        count: Int,
        probe: AsyncEventProbe<TransportConnectionID>,
        host: (Int) -> String = { "198.51.100.\($0)" }
    ) -> [AdmissionSpyConnection] {
        (1 ... count)
            .map {
                AdmissionSpyConnection(
                    id: TransportConnectionID(UInt64($0)),
                    peer: TransportAddress(host: host($0), port: 0),
                    probe: probe
                )
            }
    }

    @Test(
        "a gated backbone never yields a connection over the cap, so no serve task is created for it",
        .timeLimit(TestLivenessBudget.timeLimit(minutes: 1)),
        arguments: [(cap: 1, excess: 3), (cap: 2, excess: 3), (cap: 4, excess: 4)]
    )
    func overCapConnectionsAreNeverQueuedOrServed(
        _ scenario: (cap: Int, excess: Int)
    ) async throws {
        // Distinct peer hosts and a generous per-client budget, so only the GLOBAL ceiling can trip.
        let limits = HTTPLimits(
            maxConnectionsPerClient: 1_000,
            maxConnections: scenario.cap
        )
        let probe = AsyncEventProbe<TransportConnectionID>()
        let inbound = Self.makeInbound(count: scenario.cap + scenario.excess, probe: probe)
        let transport = AdmissionSpyTransport(inbound: inbound)
        let responder = ClosureResponder { _, _, _ in ServerResponse(HTTPResponse(status: .ok)) }
        let server = HTTPServer(transport: transport, responder: responder, limits: limits)

        let run = Task { try? await server.run() }
        // Every connection has had its admission decided: an admitted one recorded a read, a refused
        // one recorded its close at the accept point.
        _ = try await probe.wait(forAtLeast: inbound.count)

        // The stream itself never carried more than the ceiling — the bound the audit asked for is on
        // the QUEUE, not merely on what gets served.
        #expect(transport.yielded.count == scenario.cap)
        let served = inbound.filter(\.wasRead)
        #expect(served.count == scenario.cap)
        // The finding's core claim: not one of the rejects was ever read from, so not one of them had
        // a serve task created for it. Every one was closed at the accept point instead.
        for connection in inbound where !served.contains(where: { $0 === connection }) {
            #expect(!connection.wasRead, "a rejected connection was served")
            #expect(connection.isClosed, "a rejected connection was not closed at accept time")
        }

        run.cancel()
        _ = await run.value
    }

    @Test(
        "the server adopts the transport's ticket instead of charging a second slot",
        .timeLimit(TestLivenessBudget.timeLimit(minutes: 1))
    )
    func adoptedTicketIsNotDoubleCharged() async throws {
        // The cap is exactly the number of inbound connections: if the server charged its own slot on
        // top of the transport's, the second connection would be refused and never served.
        let limits = HTTPLimits(maxConnectionsPerClient: 1_000, maxConnections: 2)
        let probe = AsyncEventProbe<TransportConnectionID>()
        let inbound = Self.makeInbound(count: 2, probe: probe)
        let transport = AdmissionSpyTransport(inbound: inbound)
        let responder = ClosureResponder { _, _, _ in ServerResponse(HTTPResponse(status: .ok)) }
        let server = HTTPServer(transport: transport, responder: responder, limits: limits)

        let run = Task { try? await server.run() }
        _ = try await probe.wait(forAtLeast: 2)

        let readCount = inbound.filter(\.wasRead).count
        #expect(transport.yielded.count == 2)
        #expect(readCount == 2, "an adopted ticket was double-charged")
        #expect(server.admission.counts.total == 2, "the gate counts each connection exactly once")

        run.cancel()
        _ = await run.value
    }

    @Test(
        "an ungated backbone's connections are still capped, before any serve work",
        .timeLimit(TestLivenessBudget.timeLimit(minutes: 1))
    )
    func ungatedBackboneIsCappedByTheServer() async throws {
        // `FakeTransport` charges nothing (its connections are built by the test, so it has no accept
        // point). The server must therefore charge on dequeue — still before it reads a single byte —
        // so the ceiling holds on every backbone.
        let limits = HTTPLimits(maxConnectionsPerClient: 1_000, maxConnections: 2)
        let probe = AsyncEventProbe<TransportConnectionID>()
        let inbound = Self.makeInbound(count: 5, probe: probe)
        let responder = ClosureResponder { _, _, _ in ServerResponse(HTTPResponse(status: .ok)) }
        let server = HTTPServer(
            transport: FakeTransport(connections: inbound),
            responder: responder,
            limits: limits
        )

        let run = Task { try? await server.run() }
        _ = try await probe.wait(forAtLeast: 5)

        let readCount = inbound.filter(\.wasRead).count
        let closedCount = inbound.filter(\.isClosed).count
        #expect(readCount == 2)
        #expect(closedCount == 3)
        for connection in inbound where !connection.wasRead {
            #expect(connection.isClosed, "an over-cap connection was neither served nor closed")
        }

        run.cancel()
        _ = await run.value
    }

    @Test(
        "a per-host rejection does not stop the gate admitting other hosts",
        .timeLimit(TestLivenessBudget.timeLimit(minutes: 1))
    )
    func perHostRejectionDoesNotStarveOtherHosts() async throws {
        // One noisy source (three connections, per-client cap 1) interleaved with two other peers: the
        // noisy peer loses two connections, everyone else is served.
        let limits = HTTPLimits(maxConnectionsPerClient: 1, maxConnections: 1_000)
        let probe = AsyncEventProbe<TransportConnectionID>()
        let hosts = ["203.0.113.9", "203.0.113.9", "198.51.100.1", "203.0.113.9", "198.51.100.2"]
        let inbound = hosts.enumerated()
            .map { index, host in
                AdmissionSpyConnection(
                    id: TransportConnectionID(UInt64(index + 1)),
                    peer: TransportAddress(host: host, port: 0),
                    probe: probe
                )
            }
        let transport = AdmissionSpyTransport(inbound: inbound)
        let responder = ClosureResponder { _, _, _ in ServerResponse(HTTPResponse(status: .ok)) }
        let server = HTTPServer(transport: transport, responder: responder, limits: limits)

        let run = Task { try? await server.run() }
        _ = try await probe.wait(forAtLeast: inbound.count)

        let readCount = inbound.filter(\.wasRead).count
        #expect(readCount == 3, "one slot per host should have been served")
        #expect(inbound[0].wasRead)  // the noisy peer's first connection
        #expect(!inbound[1].wasRead)  // over its per-host cap
        #expect(inbound[2].wasRead)  // a different peer, unaffected
        #expect(!inbound[3].wasRead)
        #expect(inbound[4].wasRead)  // and another

        run.cancel()
        _ = await run.value
    }
}
