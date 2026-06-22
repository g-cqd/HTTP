//
//  PropertyToolkitTests.swift
//  HTTPTestSupportTests
//
//  Self-tests for the ported property/fuzz/oracle toolkit: a seeded RNG that reproduces, a
//  deterministic byte mutator, the constrained-stack runner + depth sweep, the assertion oracles, and
//  the allocation counter.
//

import Testing

@testable import HTTPTestSupport

private enum SampleError: Error, Equatable { case bad(Int) }

@Suite("Property toolkit")
struct PropertyToolkitTests {

    @Test
    func `SeededRNG reproduces the same stream for a fixed seed`() {
        var a = SeededRNG(seed: 42)
        var b = SeededRNG(seed: 42)
        let streamA = (0..<8).map { _ in a.next() }
        let streamB = (0..<8).map { _ in b.next() }
        #expect(streamA == streamB)
    }

    @Test
    func `Seed.named is stable and distinguishes names`() {
        #expect(Seed.named("http1.request") == Seed.named("http1.request"))
        #expect(Seed.named("http1.request") != Seed.named("http2.frame"))
    }

    @Test
    func `ByteMutator is deterministic under a fixed seed`() {
        let mutator = ByteMutator()
        var r1 = SeededRNG(seed: 7)
        var r2 = SeededRNG(seed: 7)
        var b1 = Array("hello world".utf8)
        var b2 = b1
        mutator.apply(5, to: &b1, using: &r1)
        mutator.apply(5, to: &b2, using: &r2)
        #expect(b1 == b2)
    }

    @Test
    func `fuzzNeverTraps runs the requested iterations`() {
        let report = fuzzNeverTraps(
            seed: .named("toolkit"), iterations: 50, corpus: { [1, 2, 3] }, exercise: { _ in })
        #expect(report.iterations == 50)
    }

    @Test
    func `runOnConstrainedStack returns the body's value`() {
        #expect(runOnConstrainedStack { 21 + 21 } == 42)
    }

    @Test
    func `DepthSweep straddles each cap`() {
        let sweep = DepthSweep.around(100, upTo: 300)
        #expect(sweep.depths.contains(99))
        #expect(sweep.depths.contains(100))
        #expect(sweep.depths.contains(101))
        #expect(sweep.depths.allSatisfy { $0 >= 1 && $0 <= 300 })
    }

    @Test
    func `expectThrows checks the error type and payload`() {
        let caught = expectThrows(
            { () throws -> Int in throw SampleError.bad(7) },
            where: { (error: SampleError) in error == .bad(7) })
        #expect(caught == .bad(7))
    }

    @Test
    func `expectRoundTripIdentity accepts an identity round trip`() {
        expectRoundTripIdentity(Array("ping".utf8)) { $0 }  // records no issue
    }

    @Test
    func `mallocDelta measures a growing buffer where counting is available`() {
        guard allocationCountingAvailable else { return }
        var sink = [UInt8]()
        sink.append(0)  // warm up the first buffer
        let count = mallocDelta { for _ in 0..<2000 { sink.append(0) } }
        #expect((count ?? 0) >= 1)  // geometric growth reallocates at least once
    }
}
