//
//  HTTPLimitsArithmeticBoundsTests.swift
//  HTTPCoreTests
//
//  Audit R5-VAL — a bound has to leave room for the arithmetic the value later participates in.
//
//  The CR-F15 validation bounds each limit *in isolation*: `maxFieldSize` may be anything in
//  `1 ... Int.max`, and every value in that range is individually coherent. But two of these limits are
//  later added to something, and a bound whose top is `Int.max` guarantees that addition traps — a
//  configuration that passes `init(validating:)` and then crashes the server on its first request is
//  strictly worse than one that is refused (CWE-190, integer overflow; CWE-1284, invalid quantity).
//
//  Two sums exist today:
//    * `HTTPLimits.effectiveRequestBodyWindow` = `maxFieldSize + 16_384`
//    * `HTTPServer+RequestReader`'s header ceiling = `maxRequestLineLength + maxHeaderListSize`
//
//  So each participant's bound now carries the headroom its sum needs, and both the clamping and the
//  throwing initializer inherit that from the one `Bounds` table. These tests walk `Int.max` and its
//  neighbours across every arithmetic-participating limit; the *clamping* half is the load-bearing one,
//  because it is the path that would otherwise hand a live server the trapping value.
//

import Testing

@testable import HTTPCore

@Suite("HTTPLimits — bounds leave headroom for the arithmetic they feed (R5-VAL)")
struct HTTPLimitsArithmeticBoundsTests {
    /// The values that sit at, just below, and just under the headroom of an `Int.max`-topped bound.
    ///
    /// `Int.max - 16_384` is the exact boundary for `maxFieldSize`; the others bracket it so an
    /// off-by-one in either direction shows up as a trap rather than as a passing test.
    private static let extremes: [Int] = [
        .max,
        .max - 1,
        .max - 16_383,
        .max - 16_384,
        .max - 16_385,
        .max / 2,
        .max / 2 + 1,
        .max / 2 - 1
    ]

    @Test("a clamped maxFieldSize never overflows effectiveRequestBodyWindow", arguments: extremes)
    func fieldSizeLeavesRoomForTheBodyWindow(_ value: Int) {
        let limits = HTTPLimits.default.with { $0.maxFieldSize = value }
        // The trap this reproduces: `maxFieldSize + 16_384` on a value clamped to `Int.max`.
        _ = limits.effectiveRequestBodyWindow
        #expect(limits.maxFieldSize <= Int.max - 16_384)
        #expect(limits.effectiveRequestBodyWindow >= limits.requestBodyWindowSize)
    }

    @Test(
        "a validated maxFieldSize never overflows effectiveRequestBodyWindow",
        arguments: extremes
    )
    func validatedFieldSizeLeavesRoomForTheBodyWindow(_ value: Int) {
        var draft = HTTPLimits.Draft(HTTPLimits.default)
        draft.maxFieldSize = value
        guard let limits = try? HTTPLimits(validating: draft) else {
            return  // refused outright, which is the other acceptable answer
        }
        _ = limits.effectiveRequestBodyWindow
        #expect(limits.maxFieldSize <= Int.max - 16_384)
    }

    @Test(
        "a clamped request line + header list never overflows the header ceiling",
        arguments: extremes,
        [Int.max, Int.max / 2, 0, 64 * 1_024]
    )
    func headerCeilingNeverOverflows(_ requestLine: Int, _ headerList: Int) {
        let limits = HTTPLimits.default.with {
            $0.maxRequestLineLength = requestLine
            $0.maxHeaderListSize = headerList
        }
        // The trap this reproduces: the reader's `maxRequestLineLength + maxHeaderListSize` ceiling.
        let ceiling = limits.maxRequestLineLength + limits.maxHeaderListSize
        #expect(ceiling > 0)
    }

    @Test(
        "a validated request line + header list never overflows the header ceiling",
        arguments: extremes
    )
    func validatedHeaderCeilingNeverOverflows(_ value: Int) {
        var draft = HTTPLimits.Draft(HTTPLimits.default)
        draft.maxRequestLineLength = value
        draft.maxHeaderListSize = value
        guard let limits = try? HTTPLimits(validating: draft) else {
            return  // refused outright, which is the other acceptable answer
        }
        let ceiling = limits.maxRequestLineLength + limits.maxHeaderListSize
        #expect(ceiling > 0)
    }

    @Test("the presets still satisfy the tightened bounds")
    func presetsStillValidate() throws {
        for preset in [HTTPLimits.default, .highThroughput, .hardened] {
            _ = try HTTPLimits(validating: HTTPLimits.Draft(preset))
            _ = preset.effectiveRequestBodyWindow
            #expect(preset.maxRequestLineLength + preset.maxHeaderListSize > 0)
        }
    }
}
