//
//  HTTP2ConsumptionSignalTests.swift
//  HTTPServerTests
//
//  ``HTTP2ConsumptionSignal`` — the handler → serve-loop byte report behind consumption-gated HTTP/2
//  flow control (2026-07-31 audit F2/F4, ADR 0006).
//
//  Two properties are load-bearing and neither is obvious from the type's shape: the wakeup edge
//  COALESCES (a handler draining a large body must not post one mailbox wakeup per chunk), and it is
//  nonetheless LOSSLESS (clear-then-drain, so a report racing a drain re-arms the edge rather than
//  being banked with no wakeup pending). Getting the second wrong would strand a stream on credit it
//  had already earned until some unrelated event happened to wake the loop.
//

import Synchronization
import Testing

@testable import HTTPServer

@Suite("ADR 0006 — HTTP/2 consumption signal")
struct HTTP2ConsumptionSignalTests {
    @Test("records accumulate and drain exactly once")
    func accumulatesAndDrains() {
        let signal = HTTP2ConsumptionSignal {
            // The edge is not under test here — only the accumulate/drain arithmetic.
        }
        signal.record(100)
        signal.record(23)
        #expect(signal.takeAll() == 123)
        #expect(signal.takeAll() == 0)  // drained, not replayed
    }

    @Test("a zero or negative report is ignored and raises no edge")
    func ignoresNonPositiveReports() {
        let counter = Counter()
        let signal = HTTP2ConsumptionSignal { counter.bump() }
        signal.record(0)
        signal.record(-5)
        #expect(counter.value == 0)
        #expect(signal.takeAll() == 0)
    }

    @Test("the wakeup edge coalesces — many records before a drain post one wakeup")
    func edgeCoalesces() {
        let counter = Counter()
        let signal = HTTP2ConsumptionSignal { counter.bump() }
        for _ in 0 ..< 64 {
            signal.record(1_024)
        }
        // 64 chunks taken, ONE mailbox wakeup: the serve loop credits the whole batch in a single turn.
        // Without coalescing a 64 MiB upload at 16 KiB frames would post 4,096 wakeups.
        #expect(counter.value == 1)
        #expect(signal.takeAll() == 64 * 1_024)
    }

    @Test("the edge re-arms after a drain, so a later record wakes the loop again")
    func edgeReArmsAfterDrain() {
        let counter = Counter()
        let signal = HTTP2ConsumptionSignal { counter.bump() }
        signal.record(10)
        #expect(counter.value == 1)
        _ = signal.takeAll()
        signal.record(10)
        #expect(counter.value == 2)
    }

    @Test("a record racing a drain is never lost — it is drained or it re-signals")
    func concurrentRecordsAreNeverLost() async {
        let counter = Counter()
        let signal = HTTP2ConsumptionSignal { counter.bump() }
        let reports = 2_000

        // One producer reporting while one consumer drains — the real topology (a handler's iterator
        // against the serve loop). The invariant: every reported octet is eventually observed, and the
        // last drain never leaves bytes banked behind a lowered edge.
        async let produced: Void = {
            for _ in 0 ..< reports {
                signal.record(1)
                await Task.yield()
            }
        }()
        async let drained: Int = {
            var total = 0
            while total < reports {
                total += signal.takeAll()
                await Task.yield()
            }
            return total
        }()

        await produced
        let total = await drained + signal.takeAll()
        #expect(total == reports)
        #expect(counter.value >= 1)  // at least one edge; how many is a scheduling detail
    }

    /// A trivial call counter — the signal's `notify` is `@Sendable`, so it cannot capture a `var`.
    private final class Counter: Sendable {
        private let count = Atomic<Int>(0)

        var value: Int { count.load(ordering: .relaxed) }

        func bump() { count.wrappingAdd(1, ordering: .relaxed) }

        deinit {
            // No teardown beyond ARC.
        }
    }
}
