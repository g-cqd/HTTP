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
    /// A byte watermark far above anything these messages retain, so the tests that predate it still
    /// exercise the *count* route they were written for.
    private static let roomy = 1 << 20

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
        let mailbox = WebSocketBroadcastMailbox(capacity: 4, maxBytes: Self.roomy)
        let edge = EdgeCounter()
        for index in 0 ..< 4 {
            #expect(mailbox.deposit(.text("m\(index)"), signal: edge.signal) == .enqueued)
        }
        #expect(mailbox.drain() == (0 ..< 4).map { WebSocketMessage.text("m\($0)") })
        #expect(mailbox.droppedCount == 0)
    }

    @Test("at capacity the oldest is evicted and the eviction is reported and counted")
    func evictsOldestAndCounts() {
        let mailbox = WebSocketBroadcastMailbox(capacity: 2, maxBytes: Self.roomy)
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
        let mailbox = WebSocketBroadcastMailbox(capacity: 64, maxBytes: Self.roomy)
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
        let mailbox = WebSocketBroadcastMailbox(capacity: 8, maxBytes: Self.roomy)
        let edge = EdgeCounter()
        mailbox.deposit(.text("first"), signal: edge.signal)
        #expect(mailbox.drain() == [.text("first")])
        mailbox.deposit(.text("second"), signal: edge.signal)
        #expect(edge.count == 2)
        #expect(mailbox.drain() == [.text("second")])
        #expect(mailbox.queuedCount == 0)
    }

    /// The addendum's finding: a count bound says nothing about retained memory.
    ///
    /// Every message here is well inside the 64-slot count bound — the mailbox never comes close to
    /// it — so a count-only mailbox retains all 12, i.e. 360 octets against a 100-octet budget. With
    /// the watermark the ring evicts, counts the eviction, and stays under it.
    @Test("the byte watermark evicts messages the count bound would have kept")
    func evictsOnTheByteWatermark() {
        let mailbox = WebSocketBroadcastMailbox(capacity: 64, maxBytes: 100)
        let edge = EdgeCounter()
        let payload = String(repeating: "x", count: 30)
        for index in 0 ..< 3 {
            #expect(mailbox.deposit(.text("\(index)" + payload), signal: edge.signal) == .enqueued)
        }
        #expect(mailbox.queuedBytes == 93)
        #expect(mailbox.queuedCount == 3)

        // The fourth 31-octet message would put retention at 124 > 100, so the oldest goes.
        #expect(mailbox.deposit(.text("3" + payload), signal: edge.signal) == .droppedOldest)
        #expect(mailbox.queuedBytes <= 100)
        #expect(mailbox.queuedCount == 3)  // still nowhere near the 64-slot bound
        #expect(mailbox.droppedCount == 1)
        #expect(mailbox.drain() == (1 ... 3).map { WebSocketMessage.text("\($0)" + payload) })
        #expect(mailbox.queuedBytes == 0)  // a drain releases the whole budget
    }

    /// Binary and text are charged the same way — payload octets, measured once on deposit.
    @Test(
        "retention is charged in payload octets for both message kinds",
        arguments: [16, 64, 256]
    )
    func chargesPayloadOctets(size: Int) {
        let mailbox = WebSocketBroadcastMailbox(capacity: 64, maxBytes: Self.roomy)
        let edge = EdgeCounter()
        mailbox.deposit(.text(String(repeating: "y", count: size)), signal: edge.signal)
        mailbox.deposit(.binary([UInt8](repeating: 0xAB, count: size)), signal: edge.signal)
        #expect(mailbox.queuedBytes == 2 * size)
    }

    /// A single message larger than the whole watermark is still delivered, against an emptied ring.
    ///
    /// Refusing it would lose the message *and* leave the queue empty, and the connection is being
    /// closed by the drop either way. Retention is therefore bounded by `maxBytes` plus one maximum
    /// message, which `effectiveWebSocketMessageSize` already caps.
    @Test("a message larger than the watermark still lands, having emptied the ring")
    func anOversizedMessageStillLands() {
        let mailbox = WebSocketBroadcastMailbox(capacity: 8, maxBytes: 32)
        let edge = EdgeCounter()
        mailbox.deposit(.text("small"), signal: edge.signal)
        let huge = String(repeating: "z", count: 200)
        #expect(mailbox.deposit(.text(huge), signal: edge.signal) == .droppedOldest)
        #expect(mailbox.drain() == [.text(huge)])
        #expect(mailbox.droppedCount == 1)
    }

    @Test("a zero or negative capacity is clamped to one rather than trapping")
    func clampsDegenerateCapacity() {
        let mailbox = WebSocketBroadcastMailbox(capacity: 0, maxBytes: Self.roomy)
        let edge = EdgeCounter()
        #expect(mailbox.deposit(.text("a"), signal: edge.signal) == .enqueued)
        #expect(mailbox.deposit(.text("b"), signal: edge.signal) == .droppedOldest)
        #expect(mailbox.drain() == [.text("b")])
    }
}
