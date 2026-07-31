//
//  HTTP3StreamInboxTests.swift
//  HTTPServerTests
//
//  Audit REG-2 — the primitive an HTTP/3 stream's serve loop waits on so it hears BOTH its inbound
//  QUIC octets and the routed events another stream's task deposited for it (RFC 9204 §2.1.2).
//
//  The properties pinned here are the ones the serve loop relies on and the ones a hand-rolled
//  merge gets wrong: routed mail is never starved by inbound octets, exactly one chunk is ever in
//  flight (the backpressure that replaces the loop's own `receive()` pacing), a queued chunk is still
//  delivered after the inbox closes, and a parked party is resumed by cancellation rather than left
//  wedged — the teardown property the whole fix hinges on.
//

import HTTPTestSupport
import Testing

@testable import HTTPServer

@Suite("HTTP/3 stream inbox — the merged wakeup mailbox (audit REG-2)")
struct HTTP3StreamInboxTests {
    @Test("a routed signal wakes a loop parked with no inbound bytes coming")
    func routedSignalWakesAParkedConsumer() async throws {
        let inbox = HTTP3StreamInbox()
        let parked = AsyncEventProbe<HTTP3StreamInbox.Wakeup>()
        let consumer = Task { parked.record(await inbox.next()) }
        defer { consumer.cancel() }

        // Nothing is offered on the inbound side — this is exactly the `fin:false` blocked-QPACK case.
        try await Self.settle { inbox.isConsumerParked }
        inbox.signalRouted()

        let woken = try await parked.wait(forAtLeast: 1)
        #expect(woken == [.routed])
    }

    @Test("routed mail is taken before an already-queued chunk")
    func routedMailPrecedesAQueuedChunk() async {
        let inbox = HTTP3StreamInbox()
        #expect(await inbox.offer([0x01], fin: false))
        inbox.signalRouted()

        // The routed events were produced by the engine before this chunk has even been fed to it.
        #expect(await inbox.next() == .routed)
        #expect(await inbox.next() == .inbound(bytes: [0x01], fin: false))
    }

    @Test("a second offer parks until the loop takes the first — one chunk in flight")
    func theProducerParksWhileAChunkIsPending() async throws {
        let inbox = HTTP3StreamInbox()
        let offered = AsyncEventProbe<Int>()
        #expect(await inbox.offer([0x01], fin: false))

        let producer = Task {
            _ = await inbox.offer([0x02], fin: true)
            offered.record(2)
        }
        defer { producer.cancel() }

        try await Self.settle { inbox.isProducerParked }
        #expect(offered.isEmpty)  // parked: the loop still holds chunk 1

        #expect(await inbox.next() == .inbound(bytes: [0x01], fin: false))
        _ = try await offered.wait(forAtLeast: 1)
        #expect(await inbox.next() == .inbound(bytes: [0x02], fin: true))
    }

    @Test("closing still delivers the queued chunk, then reports the end")
    func closingDrainsTheQueuedChunkFirst() async {
        let inbox = HTTP3StreamInbox()
        #expect(await inbox.offer([0x01], fin: false))
        inbox.close()

        #expect(await inbox.next() == .inbound(bytes: [0x01], fin: false))
        #expect(await inbox.next() == .ended)
        #expect(await inbox.offer([0x02], fin: false) == false)  // refused once closed
    }

    @Test("cancelling a parked consumer unwinds it instead of wedging the stream")
    func aCancelledConsumerUnwinds() async throws {
        let inbox = HTTP3StreamInbox()
        let woken = AsyncEventProbe<HTTP3StreamInbox.Wakeup>()
        let consumer = Task { woken.record(await inbox.next()) }

        try await Self.settle { inbox.isConsumerParked }
        consumer.cancel()  // connection teardown, with nothing ever arriving

        #expect(try await woken.wait(forAtLeast: 1) == [.ended])
    }

    @Test("cancelling a parked producer unwinds it too")
    func aCancelledProducerUnwinds() async throws {
        let inbox = HTTP3StreamInbox()
        let finished = AsyncEventProbe<Bool>()
        #expect(await inbox.offer([0x01], fin: false))

        let producer = Task { finished.record(await inbox.offer([0x02], fin: false)) }
        try await Self.settle { inbox.isProducerParked }
        producer.cancel()

        #expect(try await finished.wait(forAtLeast: 1) == [false])
    }

    /// Polls `condition` until it holds, failing the test if the budget runs out.
    ///
    /// The budget exhausting is a *failure*, not a quiet return: a vacuously satisfied precondition
    /// would let the assertions below pass without ever exercising the parked path.
    private static func settle(until condition: @Sendable () -> Bool) async throws {
        for _ in 0 ..< 200 where !condition() {
            try await Task.sleep(for: .milliseconds(5))
        }
        #expect(condition(), "settle budget exhausted with the condition still false")
    }
}
