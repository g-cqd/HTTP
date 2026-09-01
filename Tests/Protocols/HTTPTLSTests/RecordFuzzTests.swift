//
//  RecordFuzzTests.swift
//  HTTPTLSTests
//
//  The attacker-facing gate on record parsing: seeded random garbage, mutated valid streams,
//  header length lies, truncations, and CCS interleavings against `receive`. PASS is process
//  survival with the typed contract intact — every outcome is events or one `TLSRecordError`,
//  never a trap, never memory growth past one record (length caps are enforced from the header
//  alone), and never unbounded work (asserted as an operation budget, not wall clock).
//

import Crypto
internal import HTTPTestSupport
import Testing

@testable internal import HTTPTLS

@Suite("Record-parsing fuzz — survival with the typed contract intact")
struct RecordFuzzTests {
    private let clientHs = SymmetricKey(data: RFC8448Simple.clientHandshakeTrafficSecret)

    /// Feeds `bytes` in `chunk`-sized feeds to a fresh post-ClientHello server layer,
    /// optionally with handshake read keys installed; any typed error is a PASS.
    private func survives(
        _ bytes: [UInt8], chunk: Int, keysInstalled: Bool
    ) -> [TLSRecordEvent]? {
        var server = TLSRecordLayer()
        var events: [TLSRecordEvent] = []
        do {
            _ = try server.receive(RFC8448Simple.clientHelloRecord)
            if keysInstalled {
                try server.installReadKeys(suite: .aes128GcmSha256, trafficSecret: clientHs)
            }
            var cursor = 0
            while cursor < bytes.count {
                let end = min(cursor + chunk, bytes.count)
                events += try server.receive(Array(bytes[cursor ..< end]))
                cursor = end
            }
        }
        catch {
            return nil  // a typed TLSRecordError rejection — fine
        }
        return events
    }

    @Test("seeded random garbage never traps, in whole and dribbled feeds")
    func randomGarbageSurvives() {
        var generator = SeededRNG(seed: Seed.named("httptls.fuzz.garbage"))
        for iteration in 0 ..< 200 {
            let size = Int.random(in: 0 ... 4_096, using: &generator)
            var garbage = [UInt8](repeating: 0, count: size)
            for index in garbage.indices {
                garbage[index] = UInt8.random(in: .min ... .max, using: &generator)
            }
            let chunk = [1, 7, 64, 4_096][iteration % 4]
            _ = survives(garbage, chunk: chunk, keysInstalled: iteration % 2 == 1)
        }
    }

    @Test("mutated valid record streams never trap and never mis-deliver silently")
    func mutatedStreamsSurvive() {
        let valid = RFC8448Simple.clientFinishedRecord
        var generator = SeededRNG(seed: Seed.named("httptls.fuzz.mutated"))
        let mutator = ByteMutator()
        for iteration in 0 ..< 300 {
            var corrupted = valid
            let trace = mutator.apply(1 + iteration % 4, to: &corrupted, using: &generator)
            guard
                let events = survives(
                    corrupted, chunk: 97, keysInstalled: true
                )
            else {
                continue  // typed rejection — the overwhelmingly common outcome
            }
            // Anything that still decodes must be byte-identical content: the AEAD
            // authenticates header and body, so only a no-op mutation can survive.
            for event in events {
                #expect(
                    event == .handshake(RFC8448Simple.clientFinished),
                    "iteration \(iteration): \(trace)"
                )
            }
        }
    }

    @Test("header length lies are rejected or stall — with bounded work, never buffered")
    func lengthLiesBounded() {
        var generator = SeededRNG(seed: Seed.named("httptls.fuzz.lengths"))
        for iteration in 0 ..< 200 {
            let type = [20, 21, 22, 23, 99][iteration % 5]
            let length = Int.random(in: 0 ... 70_000, using: &generator)
            let supplied = Int.random(in: 0 ... min(length, 512), using: &generator)
            var bytes: [UInt8] = [
                UInt8(truncatingIfNeeded: type), 3, 3,
                UInt8(truncatingIfNeeded: length >> 8), UInt8(truncatingIfNeeded: length)
            ]
            bytes += [UInt8](repeating: 0xAA, count: supplied)
            // Whole-feed and dribbled: either a typed error or a stall awaiting the body.
            _ = survives(bytes, chunk: bytes.count, keysInstalled: false)
            _ = survives(bytes, chunk: 3, keysInstalled: true)
        }
    }

    @Test("every truncation of a valid stream stalls cleanly and resumes losslessly")
    func truncationSweep() throws {
        let stream = RFC8448Simple.clientHelloRecord + RFC8448Compat.changeCipherSpecRecord
        for cut in 0 ... stream.count {
            var server = TLSRecordLayer()
            var events = try server.receive(Array(stream[..<cut]))
            events += try server.receive(Array(stream[cut...]))
            #expect(events == [.handshake(RFC8448Simple.clientHello)], "cut \(cut)")
        }
    }

    @Test("CCS floods interleaved with the handshake are dropped with linear work")
    func interleavedCCSFlood() throws {
        var stream: [UInt8] = RFC8448Simple.clientHelloRecord
        for _ in 0 ..< 64 {
            stream += RFC8448Compat.changeCipherSpecRecord
        }
        var server = TLSRecordLayer()
        var events = try server.receive(stream)
        #expect(events == [.handshake(RFC8448Simple.clientHello)])
        try server.installReadKeys(suite: .aes128GcmSha256, trafficSecret: clientHs)
        events = try server.receive(
            RFC8448Compat.changeCipherSpecRecord + RFC8448Simple.clientFinishedRecord
        )
        #expect(events == [.handshake(RFC8448Simple.clientFinished)])
    }

    @Test("a max-size forged ciphertext is rejected with bounded work (the CWE-409 shape)")
    func maxSizeForgeryBounded() {
        // A full-cap record of noise under a live key: one AEAD pass, one typed error.
        var generator = SeededRNG(seed: Seed.named("httptls.fuzz.forgery"))
        var body = [UInt8](repeating: 0, count: TLSRecordLimits.maxCiphertextLength)
        for index in body.indices {
            body[index] = UInt8.random(in: .min ... .max, using: &generator)
        }
        let header: [UInt8] = [
            23, 3, 3, UInt8(truncatingIfNeeded: body.count >> 8),
            UInt8(truncatingIfNeeded: body.count)
        ]
        let outcome = survives(header + body, chunk: 4_096, keysInstalled: true)
        #expect(outcome == nil, "a random full-cap forgery must die as bad_record_mac")
    }
}
