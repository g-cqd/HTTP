//
//  WebSocketBroadcastMailboxTests.swift
//  HTTPServerTests
//
//  The droppable half of the WebSocket wakeup split (2026-07-31 audit, finding 1). Two properties here
//  are subtle enough to deserve isolation from the end-to-end pump test: the wakeup edge is *coalesced*
//  (so a publish storm cannot inflate the pump's mailbox), and clear-then-drain happens in one critical
//  section (so a deposit racing a drain can neither be stranded nor lose its edge).
//

internal import Synchronization
import Testing
import WebSocket

@testable import HTTPServer

@Suite("HTTPServer — WebSocketBroadcastMailbox (bounded, counted drop)")
struct WebSocketBroadcastMailboxTests {
    /// Counts wakeup-edge signals, so every test observes the edge instead of discarding it.
    private final class EdgeCounter: Sendable {
        private let raised = Mutex(0)

        var count: Int { raised.withLock(\.self) }

        func signal() { raised.withLock { $0 += 1 } }

        deinit {
            // No teardown beyond ARC.
        }
    }

    @Test("deposits within capacity are all returned by one drain, in order")
    func drainsInOrder() {
        let mailbox = WebSocketBroadcastMailbox(capacity: 4)
        let edge = EdgeCounter()
        for index in 0 ..< 4 {
            #expect(mailbox.deposit(.text("m\(index)"), signal: edge.signal) == .enqueued)
        }
        #expect(mailbox.drain() == (0 ..< 4).map { WebSocketMessage.text("m\($0)") })
        #expect(mailbox.droppedCount == 0)
    }

    @Test("at capacity the oldest is evicted and the eviction is reported and counted")
    func evictsOldestAndCounts() {
        let mailbox = WebSocketBroadcastMailbox(capacity: 2)
        let edge = EdgeCounter()
        #expect(mailbox.deposit(.text("a"), signal: edge.signal) == .enqueued)
        #expect(mailbox.deposit(.text("b"), signal: edge.signal) == .enqueued)
        #expect(mailbox.deposit(.text("c"), signal: edge.signal) == .droppedOldest)
        #expect(mailbox.drain() == [.text("b"), .text("c")])
        #expect(mailbox.droppedCount == 1)
    }

    /// The property that keeps the pump's `AsyncStream` bounded: N deposits raise at most one edge.
    @Test("the wakeup edge is raised once and stays down until the next drain")
    func coalescesTheWakeupEdge() {
        let mailbox = WebSocketBroadcastMailbox(capacity: 64)
        let edge = EdgeCounter()
        for index in 0 ..< 32 {
            mailbox.deposit(.text("m\(index)"), signal: edge.signal)
        }
        #expect(edge.count == 1)
        _ = mailbox.drain()
        // The drain lowered the edge, so the next deposit signals again.
        mailbox.deposit(.text("after"), signal: edge.signal)
        #expect(edge.count == 2)
    }

    /// Clearing the edge and taking the queue must be one critical section.
    ///
    /// A deposit landing after the drain re-raises the edge and is returned by the *next* drain, so no
    /// message is ever queued with the edge down — which would strand it until unrelated traffic
    /// happened to wake the pump.
    @Test("a deposit made after a drain re-raises the edge and is returned next")
    func depositAfterDrainIsNotStranded() {
        let mailbox = WebSocketBroadcastMailbox(capacity: 8)
        let edge = EdgeCounter()
        mailbox.deposit(.text("first"), signal: edge.signal)
        #expect(mailbox.drain() == [.text("first")])
        mailbox.deposit(.text("second"), signal: edge.signal)
        #expect(edge.count == 2)
        #expect(mailbox.drain() == [.text("second")])
        #expect(mailbox.queuedCount == 0)
    }

    @Test("a zero or negative capacity is clamped to one rather than trapping")
    func clampsDegenerateCapacity() {
        let mailbox = WebSocketBroadcastMailbox(capacity: 0)
        let edge = EdgeCounter()
        #expect(mailbox.deposit(.text("a"), signal: edge.signal) == .enqueued)
        #expect(mailbox.deposit(.text("b"), signal: edge.signal) == .droppedOldest)
        #expect(mailbox.drain() == [.text("b")])
    }
}
