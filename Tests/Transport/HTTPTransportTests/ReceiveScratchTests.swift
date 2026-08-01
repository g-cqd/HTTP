//
//  ReceiveScratchTests.swift
//  HTTPTransportTests
//
//  ADD-P2 — every socket backbone sized its per-connection receive scratch to the caller's `maxLength`
//  on the connection's FIRST read and then held it for the connection's life. The server asks for
//  16 KiB, so one 87-octet `GET /` bought a 16 KiB resident buffer that stayed resident for as long as
//  the peer held the keep-alive open — the shape audit CR-F5 already removed from the server's own
//  read buffer, still present one layer down. At the default `HTTPLimits.maxConnections` of 16,384
//  that is 256 MiB of scratch nobody is reading from.
//
//  These tests pin the replacement policy: a window that starts at the floor, doubles only for a
//  connection that provably fills it, halves back after a run of quarter-full reads, and is never
//  larger than the ceiling the caller asked for. The residency oracle is `residentBytes` — the octets
//  the scratch actually holds — because allocation COUNTING cannot see the size of what was
//  allocated; `mallocByteDelta` (cumulative requested octets) is the second, independent oracle.
//
//  Standards: `read(2)` per POSIX.1-2017 (IEEE Std 1003.1-2017) is explicitly permitted to return
//  fewer octets than requested, which is what makes a window smaller than the ceiling legal at all.
//  CWE-190 (integer overflow) for the doubling; CWE-400 (uncontrolled resource consumption) for the
//  residency the policy bounds.
//

import HTTPTestSupport
import Testing

@testable import HTTPTransport

@Suite("ReceiveScratch — per-connection receive residency (ADD-P2)")
struct ReceiveScratchTests {
    /// The ceiling `HTTPServer+RequestReader` actually passes on every HTTP/1 read.
    private static let serverCeiling = 16_384

    /// A representative small request head, in octets — the read this finding is about.
    private static let smallRequest = 87

    /// One doubling step: the window before, the caller's ceiling, and the window it must produce.
    private static let doublingVectors: [(window: Int, ceiling: Int, expected: Int)] = [
        (2_048, 16_384, 4_096),
        (8_192, 16_384, 16_384),
        (16_384, 16_384, 16_384),
        (2_048, 3_000, 3_000)
    ]

    /// Runs one read through `scratch` whose "syscall" produces `produced` octets of `filler`.
    ///
    /// Returns the count the scratch reports, so a test can assert the short-read contract as well as
    /// the residency.
    @discardableResult
    private static func feed(
        _ scratch: inout ReceiveScratch,
        ceiling: Int,
        produced: Int,
        filler: UInt8 = 0x41
    ) -> Int {
        scratch.read(ceiling: ceiling) { raw in
            let count = min(produced, raw.count)
            for offset in 0 ..< count {
                raw[offset] = filler
            }
            return count
        }
    }

    /// Fills the window completely on every read, so the scratch always sees a saturating peer.
    private static func saturate(_ scratch: inout ReceiveScratch, ceiling: Int, reads: Int) {
        for _ in 0 ..< reads {
            feed(&scratch, ceiling: ceiling, produced: ceiling)
        }
    }

    @Test("a scratch that has never been read holds nothing")
    func unreadScratchIsEmpty() {
        let scratch = ReceiveScratch()
        #expect(scratch.residentBytes == 0)
    }

    // MARK: - The finding

    @Test(
        "a small first read leaves the floor resident, not the caller's ceiling",
        arguments: [1, 87, 512, ReceiveScratch.floorWindow - 1])
    func aSmallFirstReadDoesNotBuyTheCeiling(produced: Int) {
        var scratch = ReceiveScratch()
        let count = Self.feed(&scratch, ceiling: Self.serverCeiling, produced: produced)

        #expect(count == produced)
        #expect(scratch.residentBytes == ReceiveScratch.floorWindow)
        // The regression this exists to catch, spelled out: the old policy's residency.
        #expect(scratch.residentBytes < Self.serverCeiling)
    }

    @Test(
        "a connection that only ever sends small requests never grows past the floor",
        arguments: [8, 64, 512])
    func aQuietConnectionStaysAtTheFloor(reads: Int) {
        var scratch = ReceiveScratch()
        for _ in 0 ..< reads {
            Self.feed(&scratch, ceiling: Self.serverCeiling, produced: Self.smallRequest)
        }
        #expect(scratch.residentBytes == ReceiveScratch.floorWindow)
    }

    @Test("the received prefix is exactly what the read produced")
    func receivedReturnsTheReadPrefix() {
        var scratch = ReceiveScratch()
        let count = Self.feed(&scratch, ceiling: Self.serverCeiling, produced: 5, filler: 0x7A)
        #expect(Array(scratch.received(count)) == [UInt8](repeating: 0x7A, count: 5))
    }

    // MARK: - Growth

    @Test("a saturating peer doubles the window one read at a time")
    func aSaturatingPeerDoublesTheWindow() {
        var scratch = ReceiveScratch()
        var sizes: [Int] = []
        for _ in 0 ..< 5 {
            Self.feed(&scratch, ceiling: Self.serverCeiling, produced: Self.serverCeiling)
            sizes.append(scratch.residentBytes)
        }
        // Growth is deliberately LAZY — the doubled window is materialized by the next read, so a
        // connection that saturates once and then dies never pays for the buffer it earned.
        #expect(sizes == [2_048, 4_096, 8_192, 16_384, 16_384])
    }

    @Test(
        "growth never overshoots the ceiling the caller asked for",
        arguments: [1_000, 3_000, 8_192, 16_384, 65_536])
    func growthIsCappedByTheCeiling(ceiling: Int) {
        var scratch = ReceiveScratch()
        Self.saturate(&scratch, ceiling: ceiling, reads: 32)
        #expect(scratch.residentBytes <= max(ReceiveScratch.floorWindow, ceiling))
    }

    @Test(
        "the read is never longer than the ceiling, whatever the window",
        arguments: [0, 1, 7, 100, 2_047, 40_000])
    func theReadNeverExceedsTheCeiling(ceiling: Int) {
        var scratch = ReceiveScratch()
        Self.saturate(&scratch, ceiling: Self.serverCeiling, reads: 8)  // the window is at 16 KiB
        let count = Self.feed(&scratch, ceiling: ceiling, produced: Int.max)
        #expect(count <= ceiling)
    }

    @Test("a ceiling-limited read does not count as a full one, so it cannot grow the window")
    func aCeilingLimitedReadDoesNotGrowTheWindow() {
        var scratch = ReceiveScratch()
        for _ in 0 ..< 16 {
            // Saturating, but the CALLER capped it — that says nothing about what the peer has.
            Self.feed(&scratch, ceiling: 100, produced: 100)
        }
        #expect(scratch.residentBytes == ReceiveScratch.floorWindow)
    }

    // MARK: - Shrink

    @Test("a run of quarter-full reads halves the window back toward the floor")
    func aRunOfSmallReadsShrinksTheWindow() {
        var scratch = ReceiveScratch()
        Self.saturate(&scratch, ceiling: Self.serverCeiling, reads: 8)
        #expect(scratch.residentBytes == Self.serverCeiling)

        // Shrink is EAGER where growth is lazy: the whole point is the octets an idle connection is
        // holding, and a connection that shrinks and then goes quiet never reads again.
        for expected in [8_192, 4_096, 2_048, 2_048] {
            for _ in 0 ..< ReceiveScratch.shrinkRun {
                Self.feed(&scratch, ceiling: Self.serverCeiling, produced: 1)
            }
            #expect(scratch.residentBytes == expected)
        }
    }

    @Test("one full read resets the shrink run, so an active connection keeps its window")
    func aFullReadResetsTheShrinkRun() {
        var scratch = ReceiveScratch()
        Self.saturate(&scratch, ceiling: Self.serverCeiling, reads: 8)
        for _ in 0 ..< 64 {
            for _ in 0 ..< (ReceiveScratch.shrinkRun - 1) {
                Self.feed(&scratch, ceiling: Self.serverCeiling, produced: 1)
            }
            Self.feed(&scratch, ceiling: Self.serverCeiling, produced: Self.serverCeiling)
        }
        #expect(scratch.residentBytes == Self.serverCeiling)
    }

    // MARK: - Bounds

    @Test("the policy is never more resident than sizing straight to the ceiling would have been")
    func residencyNeverExceedsTheOldPolicy() {
        // The invariant the whole change rests on, over a mixed read sequence: the old policy went
        // resident at `max(ceiling)` on the first read and stayed there.
        var scratch = ReceiveScratch()
        var largest = 0
        let sequence = [(16_384, 87), (16_384, 16_384), (512, 512), (16_384, 9_000), (64, 3)]
        for (ceiling, produced) in sequence {
            Self.feed(&scratch, ceiling: ceiling, produced: produced)
            largest = max(largest, ceiling)
            #expect(scratch.residentBytes <= max(ReceiveScratch.floorWindow, largest))
        }
    }

    @Test(
        "a ceiling past Int.max / 2 cannot overflow the doubling (CWE-190)",
        arguments: [Int.max, Int.max - 1, Int.max / 2 + 1, Int.max / 2])
    func anEnormousCeilingDoesNotOverflow(ceiling: Int) {
        // Doubling `Int.max / 2 + 1` traps on `*`; the sizes below are never allocated, only computed.
        let grown = ReceiveScratch.grown(window: Int.max / 2 + 1, ceiling: ceiling)
        #expect(grown > 0)
        #expect(grown <= ceiling)
    }

    @Test(
        "the doubling stops at the ceiling and never below the current window",
        arguments: doublingVectors)
    func doublingIsMonotoneAndCapped(window: Int, ceiling: Int, expected: Int) {
        #expect(ReceiveScratch.grown(window: window, ceiling: ceiling) == expected)
    }

    @Test(
        "a non-positive read is not a small read and cannot shrink the window",
        arguments: [0, -1, -3])
    func aNonPositiveReadDoesNotShrinkTheWindow(produced: Int) {
        // `SSL_read` reports `WANT_READ` as a non-positive return, and the TLS backbone retries it
        // once it has pumped more ciphertext in. Counting those retries as quiet reads would shrink an
        // active connection's window under it.
        var scratch = ReceiveScratch()
        Self.saturate(&scratch, ceiling: Self.serverCeiling, reads: 8)
        for _ in 0 ..< (4 * ReceiveScratch.shrinkRun) {
            _ = scratch.read(ceiling: Self.serverCeiling) { _ in produced }
        }
        #expect(scratch.residentBytes == Self.serverCeiling)
    }

    @Test("a retry that precedes a real read still lets a quiet connection shrink")
    func aRetryBeforeARealReadStillShrinks() {
        var scratch = ReceiveScratch()
        Self.saturate(&scratch, ceiling: Self.serverCeiling, reads: 8)
        // The TLS decrypt loop's shape: some `WANT_READ` retries, then the read that succeeds.
        for _ in 0 ..< (3 * ReceiveScratch.shrinkRun) {
            _ = scratch.read(ceiling: Self.serverCeiling) { _ in -1 }
            Self.feed(&scratch, ceiling: Self.serverCeiling, produced: 1)
        }
        #expect(scratch.residentBytes == ReceiveScratch.floorWindow)
    }

    @Test("a zero-length read allocates nothing")
    func aZeroCeilingAllocatesNothing() {
        var scratch = ReceiveScratch()
        let count = Self.feed(&scratch, ceiling: 0, produced: 0)
        #expect(count == 0)
        #expect(scratch.residentBytes == 0)
    }

    // MARK: - Allocation oracle

    @Test("a quiet connection requests ~14 KiB fewer octets than the fixed-ceiling policy did")
    func theSavedResidencyIsCeilingMinusFloor() {
        guard allocationCountingAvailable else {
            return  // Darwin-only malloc hook
        }
        let reads = 8

        // The old policy, reproduced in the SAME loop and fill shape as the new one so the `-Onone`
        // overhead the two pay is identical and the difference between them is build-invariant.
        func oldPolicy() -> Int {
            var storage: [UInt8] = []
            for _ in 0 ..< reads {
                if storage.count < Self.serverCeiling {
                    storage = [UInt8](repeating: 0, count: Self.serverCeiling)
                }
                storage.withUnsafeMutableBytes { raw in
                    for offset in 0 ..< min(Self.smallRequest, raw.count) {
                        raw[offset] = 0x41
                    }
                }
            }
            return storage.count
        }

        func newPolicy() -> Int {
            var scratch = ReceiveScratch()
            for _ in 0 ..< reads {
                Self.feed(&scratch, ceiling: Self.serverCeiling, produced: Self.smallRequest)
            }
            return scratch.residentBytes
        }

        // Warm up first: the first call pays one-time lazy initialization the delta must not carry.
        _ = oldPolicy()
        _ = newPolicy()
        var old = 0
        var new = 0
        let oldBytes = mallocByteDelta { old = oldPolicy() }
        let newBytes = mallocByteDelta { new = newPolicy() }

        #expect(old == Self.serverCeiling)
        #expect(new == ReceiveScratch.floorWindow)
        // The DIFFERENCE is asserted because it is build-invariant (the pattern `ReactorFairnessTests`
        // established): both shapes allocate once and fill 87 octets `reads` times, so everything but
        // the buffer size cancels, and what is left is the finding.
        let saved = (oldBytes ?? 0) - (newBytes ?? 0)
        let expected = Self.serverCeiling - ReceiveScratch.floorWindow
        #expect(
            saved >= expected,
            "saved \(saved) of \(expected) octet(s); old \(oldBytes ?? -1), new \(newBytes ?? -1)"
        )
        #if !DEBUG
            // Optimized: the two shapes each request exactly one buffer plus its array header, so the
            // difference is the buffer sizes and nothing else — the exact count the guidance asks for.
            #expect(saved == expected, "measured \(saved), not exactly \(expected)")
        #endif
    }
}
