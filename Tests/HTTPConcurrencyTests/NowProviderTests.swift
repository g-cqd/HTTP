//
//  NowProviderTests.swift
//  HTTPConcurrencyTests
//
//  The monotonic-now seam: `Duration.monotonicNanoseconds` converts a limit interval to the unit a
//  `MonotonicNowProvider` measures against, saturating instead of trapping on extreme values.
//

import HTTPConcurrency
import Testing

@Suite("NowProvider")
struct NowProviderTests {

    static let cases: [(Duration, Int64)] = [
        (.seconds(1), 1_000_000_000),
        (.milliseconds(500), 500_000_000),
        (.zero, 0),
        (.nanoseconds(7), 7),
    ]

    @Test(arguments: cases)
    func `converts a duration to monotonic nanoseconds`(
        _ pair: (duration: Duration, expected: Int64)
    ) {
        #expect(pair.duration.monotonicNanoseconds == pair.expected)
    }

    @Test
    func `a negative duration clamps to zero (monotonic time never runs backwards)`() {
        #expect(Duration.seconds(-3).monotonicNanoseconds == 0)
    }

    @Test
    func `the live monotonic clock advances`() {
        let first = LiveMonotonicClock.now()
        let second = LiveMonotonicClock.now()
        #expect(second >= first)
    }
}
