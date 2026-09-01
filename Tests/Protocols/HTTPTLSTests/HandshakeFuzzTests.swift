//
//  HandshakeFuzzTests.swift
//  HTTPTLSTests
//
//  The attacker-facing gate on the MACHINE (the record layer has its own in
//  RecordFuzzTests): seeded ClientHello mutation, handshake-message mutation behind a live
//  handshake, and state-transition fuzz — random message sequences at random states. PASS is
//  the HTTPDeflate survivor semantics: every outcome is events or ONE typed error; a survivor
//  (an input that still completes a step) must have produced a semantically clean result, and
//  every error leaves the connection terminal with at most one queued alert — the funnel
//  invariant, asserted on every single iteration.
//

import Crypto
import HTTPTestSupport
import Testing

@testable internal import HTTPTLS

@Suite("Handshake fuzz — survival with the funnel invariant intact")
struct HandshakeFuzzTests {
    /// Drives one hello-record feed and asserts the funnel invariant; true when it survived.
    @discardableResult
    private static func drive(
        _ server: inout TLSServerConnection, _ bytes: [UInt8]
    ) async -> Bool {
        do {
            _ = try await server.receive(bytes)
            return true
        }
        catch {
            #expect(server.state.isTerminal, "an error must leave the machine terminal")
            let outbound = server.outboundBytes()
            // The funnel invariant: at most one PLAINTEXT alert can follow a pre-key
            // failure; nothing else may trail it.
            if outbound.count >= 7, outbound[0] == 21 {
                #expect(outbound.count == 7, "exactly one alert record after a failure")
            }
            return false
        }
    }

    @Test("mutated ClientHellos never trap and always funnel")
    func mutatedClientHellos() async {
        var generator = SeededRNG(named: "httptls.handshake.fuzz.hello")
        let mutator = ByteMutator()
        for iteration in 0 ..< 250 {
            var corrupted = RFC8448Simple.clientHello
            _ = mutator.apply(1 + iteration % 4, to: &corrupted, using: &generator)
            var server = TLSServerConnection(
                configuration: TLSServerConfiguration(), identity: P256TestIdentity()
            )
            await Self.drive(&server, TestClientHello.plaintextRecord(corrupted))
        }
    }

    @Test("mutated second-flight messages never trap and always funnel")
    func mutatedClientFlights() async throws {
        var generator = SeededRNG(named: "httptls.handshake.fuzz.flight")
        let mutator = ByteMutator()
        for iteration in 0 ..< 120 {
            var server = TLSServerConnection(
                configuration: TLSServerConfiguration(), identity: P256TestIdentity()
            )
            var client = HandshakeTestClient()
            _ = try await server.receive(try client.helloRecord())
            try client.absorb(server.outboundBytes())
            // Mutate the PLAINTEXT Finished, then seal it honestly — this exercises the
            // §4 message layer behind live keys (a ciphertext mutation only ever exercises
            // §5.2's bad_record_mac, which RecordFuzzTests already owns).
            var finished = try client.finishedMessage()
            _ = mutator.apply(1 + iteration % 3, to: &finished, using: &generator)
            let survived = await Self.drive(&server, try client.sendFlight([finished]))
            if survived, server.state == .connected {
                // A survivor must be a no-op mutation: the verify_data still matched.
                #expect(server.negotiated != nil)
            }
        }
    }

    @Test("random message-type sequences at random states always funnel, never trap")
    func stateTransitionFuzz() async throws {
        var generator = SeededRNG(named: "httptls.handshake.fuzz.transitions")
        let types: [TLSHandshakeType] = [
            .clientHello, .serverHello, .newSessionTicket, .endOfEarlyData,
            .encryptedExtensions, .certificate, .certificateRequest, .certificateVerify,
            .finished, .keyUpdate
        ]
        for _ in 0 ..< 120 {
            var server = TLSServerConnection(
                configuration: TLSServerConfiguration(), identity: P256TestIdentity()
            )
            var client = HandshakeTestClient()
            // Random depth into the legitimate handshake before the garbage starts.
            let depth = generator.uniform(3)
            if depth >= 1 {
                guard await Self.drive(&server, try client.helloRecord()) else {
                    continue
                }
                try client.absorb(server.outboundBytes())
            }
            if depth >= 2 {
                guard await Self.drive(&server, try client.finishHandshake()) else {
                    continue
                }
            }
            // A burst of random-typed messages with small random bodies, sealed under
            // whatever keys the client legitimately holds at this depth.
            for _ in 0 ..< (1 + generator.uniform(4)) {
                let type = generator.pick(types)
                var body = [UInt8](repeating: 0, count: generator.uniform(48))
                for index in body.indices {
                    body[index] = generator.byte()
                }
                let message = TLSHandshakeBuilder.message(type) { $0.raw(body) }
                let wire: [UInt8]
                if depth == 0 {
                    wire = TestClientHello.plaintextRecord(message)
                }
                else {
                    try client.record.send(handshake: message)
                    wire = client.record.outboundBytes()
                }
                guard await Self.drive(&server, wire) else {
                    break  // funneled — the invariant was asserted inside drive
                }
            }
        }
    }
}
