//
//  BoundedGrowthDecodeTests.swift
//  HTTPServerTests
//
//  The decompression-bomb bound (CWE-409) that `BrotliLinux` and `InflateLinux` share. Both wrap a
//  one-shot C decode shim that cannot report "would not fit" other than by failing, so both retry
//  into a geometrically larger destination — and both used to carry their own copy of the growth
//  schedule and the cap. This suite pins the schedule itself, which neither copy had a test for:
//  the first attempt, the doubling, the exact final attempt at the cap, and termination.
//
//  Sizes are written as literals (65_536 = the 64 KiB window) rather than as `64 * 1_024`: the
//  arithmetic inside a parameterized `@Test` argument list defeats the expression type-checker.
//

import Testing

@testable import HTTPServer

@Suite("CWE-409 — the bounded geometric-growth decode schedule")
struct BoundedGrowthDecodeTests {
    /// Every capacity the schedule asks for, plus its verdict, succeeding at `fitsAt` (nil = never).
    private static func trace(
        maxOutput: Int, fitsAt: Int? = nil
    ) -> (capacities: [Int], output: [UInt8]?) {
        var capacities: [Int] = []
        let output = BoundedGrowthDecode.run(maxOutput: maxOutput) { capacity in
            capacities.append(capacity)
            guard let fitsAt, capacity >= fitsAt else {
                return nil
            }
            return [UInt8](repeating: 0x2A, count: fitsAt)
        }
        return (capacities, output)
    }

    /// `(cap, the capacities attempted when nothing ever fits)` — the schedule, spelled out.
    private static let schedules: [(maxOutput: Int, expected: [Int])] = [
        (1, [1]),  // a cap under the window is the only attempt
        (65_536, [65_536]),  // exactly the window
        (98_304, [65_536, 98_304]),  // doubling would overshoot: jump to the cap
        (131_072, [65_536, 131_072]),  // doubling lands exactly on the cap
        (262_144, [65_536, 131_072, 262_144]),
        (307_200, [65_536, 131_072, 262_144, 307_200])
    ]

    @Test(
        "the schedule starts at min(window, cap), doubles, and ends exactly at the cap",
        arguments: schedules)
    func scheduleIsGeometricAndEndsAtTheCap(_ testCase: (maxOutput: Int, expected: [Int])) {
        let (capacities, output) = Self.trace(maxOutput: testCase.maxOutput)
        #expect(capacities == testCase.expected)
        #expect(output == nil, "nothing fitting must fail closed")
        #expect(capacities.allSatisfy { $0 <= testCase.maxOutput }, "never over the cap")
    }

    @Test(
        "a non-positive cap admits nothing and never calls the decoder",
        arguments: [0, -1, Int.min])
    func nonPositiveCapAdmitsNothing(_ maxOutput: Int) {
        let (capacities, output) = Self.trace(maxOutput: maxOutput, fitsAt: 1)
        #expect(capacities.isEmpty)
        #expect(output == nil)
    }

    @Test(
        "the first attempt that fits wins, and no larger destination is ever allocated",
        arguments: [1, 65_536, 65_537, 204_800])
    func stopsAtTheFirstFit(_ fitsAt: Int) {
        let (capacities, output) = Self.trace(maxOutput: 1_048_576, fitsAt: fitsAt)
        #expect(output?.count == fitsAt)
        #expect(capacities.last.map { $0 >= fitsAt } == true)
        #expect(capacities.dropLast().allSatisfy { $0 < fitsAt }, "no attempt after the fit")
    }

    /// `Int.max` is the case that made the schedule geometric rather than "size to the cap": the
    /// older shape computed `maxOutput + 1` and overflowed here, and sizing to the cap would have
    /// asked for an `Int.max`-octet array on every request.
    @Test("a cap of Int.max terminates without overflowing")
    func maximalCapTerminates() {
        let (capacities, output) = Self.trace(maxOutput: .max)
        #expect(output == nil)
        #expect(capacities.first == 65_536)
        #expect(capacities.last == Int.max)
        // Doubling from 64 KiB to Int.max takes log2(Int.max / 64 KiB) = 48 steps, plus the final
        // exact-cap attempt — the guarantee that the loop cannot spin.
        #expect(capacities.count <= 64)
        #expect(zip(capacities, capacities.dropFirst()).allSatisfy { $0 < $1 }, "strictly growing")
    }
}
