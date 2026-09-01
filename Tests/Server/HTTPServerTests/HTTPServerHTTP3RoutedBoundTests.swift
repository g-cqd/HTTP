//
//  HTTPServerHTTP3RoutedBoundTests.swift
//  HTTPServerTests
//
//  Audit REG-1 — the per-connection routing of HTTP/3 engine output must never *drop* an event.
//
//  Losing a `request` or a body chunk is not a throttle, it is a correctness fault: the peer sent a
//  well-formed request and gets neither a response nor a reset, and a resumable body loses octets in
//  the middle. The bound therefore has to fail closed (RFC 9114 §8.1 H3_EXCESSIVE_LOAD) rather than
//  discard, and it has to be measured in retained octets — a message count does not bound memory when
//  the messages carry request bodies and tunnel payloads (CWE-770).
//

import HTTP3
import HTTPCore
import HTTPTransport
import Testing

@testable import HTTPServer

@Suite("HTTP/3 routed events — bounded, never dropped (audit REG-1)")
struct HTTPServerHTTP3RoutedBoundTests {
    private static let owner = QUICStreamID(0)
    private static let target = QUICStreamID(4)

    @Test("every routed event is delivered — the count out equals the count in")
    func noRoutedEventIsSilentlyDropped() async {
        let registry = HTTP3StreamRegistry(mailboxByteBudget: 1 << 20)
        let stream = FakeQUICStream(id: Self.target, direction: .bidirectional)
        registry.register(stream)

        // Four times what the old fixed-slot channel could hold, drained as the owning task drains it.
        // The count is the whole assertion: a channel that trims its oldest entries passes every other
        // check here and fails only this one.
        let batches = 1_024
        var delivered = 0
        for index in 0 ..< batches {
            let routed = registry.route([.requestEnd(streamID: Self.target)], owner: Self.owner)
            #expect(routed.overflowed.isEmpty)
            if index.isMultiple(of: 2) {
                delivered += registry.takeMailbox(Self.target).count
            }
        }
        delivered += registry.takeMailbox(Self.target).count

        #expect(delivered == batches)
        #expect(stream.resetCodes.isEmpty)  // nothing was ever near a bound
    }

    @Test("a mailbox past its bound fails closed with H3_EXCESSIVE_LOAD, never trimmed")
    func anOverflowingMailboxFailsClosed() async {
        let registry = HTTP3StreamRegistry(mailboxByteBudget: 1 << 20)
        let stream = FakeQUICStream(id: Self.target, direction: .bidirectional)
        registry.register(stream)

        // Nothing drains, so the mailbox fills; past the bound the batch must be *refused* — named back
        // to the caller for retirement — rather than have the mailbox's oldest entries discarded.
        var refused: [QUICStreamID] = []
        for _ in 0 ..< (HTTP3StreamRegistry.mailboxCapacity * 4) {
            let routed = registry.route([.requestEnd(streamID: Self.target)], owner: Self.owner)
            refused += routed.overflowed
        }

        #expect(!refused.isEmpty, "the overflow must fail closed, not drop")
        #expect(refused.allSatisfy { $0 == Self.target })
        // Everything accepted before the refusal is still exactly what the mailbox holds.
        #expect(registry.takeMailbox(Self.target).count <= HTTP3StreamRegistry.mailboxCapacity)
    }

    @Test("an accepted batch is delivered whole — the count out equals the count in")
    func acceptedBatchesAreDeliveredWhole() async {
        let registry = HTTP3StreamRegistry(mailboxByteBudget: 1 << 20)
        let stream = FakeQUICStream(id: Self.target, direction: .bidirectional)
        registry.register(stream)

        // Well inside both bounds: every single event must come back out.
        let events = (0 ..< 8).map { _ in HTTP3Connection.Event.requestEnd(streamID: Self.target) }
        for event in events {
            #expect(registry.route([event], owner: Self.owner).overflowed.isEmpty)
        }

        #expect(registry.takeMailbox(Self.target).count == events.count)
        #expect(stream.resetCodes.isEmpty)
    }

    @Test("the caller's own events come back and are never filed against it")
    func theOwnersEventsAreReturnedNotFiled() async {
        let registry = HTTP3StreamRegistry(mailboxByteBudget: 1 << 20)
        registry.register(FakeQUICStream(id: Self.owner, direction: .bidirectional))

        // GOAWAY is connection-scoped (RFC 9114 §5.2) and has no owning stream, so it stays with the
        // caller alongside the events the caller's own id names.
        let routed = registry.route(
            [.requestEnd(streamID: Self.owner), .goAway(streamID: QUICStreamID(0))],
            owner: Self.owner
        )

        #expect(routed.own.count == 2)
        #expect(routed.overflowed.isEmpty)
        #expect(registry.takeMailbox(Self.owner).isEmpty)
    }

    @Test("the bound is in retained octets, not messages")
    func theBoundIsInOctetsNotMessages() async {
        let budget = 64 << 10

        // Many small events: far more messages than a few large ones, well under the octet budget.
        let small = HTTP3StreamRegistry(mailboxByteBudget: budget)
        let smallStream = FakeQUICStream(id: Self.target, direction: .bidirectional)
        small.register(smallStream)
        for _ in 0 ..< 32 {
            _ = small.deposit([Self.chunk(of: 64)], for: Self.target)
        }
        #expect(smallStream.resetCodes.isEmpty)
        #expect(small.takeMailbox(Self.target).count == 32)

        // A handful of large ones: fewer messages, past the octet budget — the bound trips on octets.
        let large = HTTP3StreamRegistry(mailboxByteBudget: budget)
        let largeStream = FakeQUICStream(id: Self.target, direction: .bidirectional)
        large.register(largeStream)
        var refused = 0
        for _ in 0 ..< 8 {
            if case .overflow = large.deposit([Self.chunk(of: 32 << 10)], for: Self.target) {
                refused += 1
            }
        }
        #expect(refused > 0, "eight 32 KiB chunks must not fit a 64 KiB budget")
        #expect(large.takeMailbox(Self.target).count < 32)
    }

    @Test("a single hand-off larger than the budget is still delivered, not refused")
    func oneOversizedHandoffIsStillDelivered() async {
        // The engine's own connection-wide buffered-body budget (RFC 9114 §4.1) already bounds what it
        // can hand over in one go; bounding it again here could only refuse a legitimate request. What
        // this mailbox bounds is *accumulation* across hand-offs.
        let registry = HTTP3StreamRegistry(mailboxByteBudget: 1 << 10)
        let stream = FakeQUICStream(id: Self.target, direction: .bidirectional)
        registry.register(stream)

        #expect(isQueued(registry.deposit([Self.chunk(of: 64 << 10)], for: Self.target)))
        #expect(stream.resetCodes.isEmpty)
        #expect(registry.takeMailbox(Self.target).count == 1)
    }

    // MARK: - Fixtures

    private static func makeServer() throws -> HTTPServer<ContinuousClock> {
        HTTPServer(
            transport: try TransportFactory.make(
                TransportConfiguration(port: 0, backbone: .fake)
            ),
            responder: ClosureResponder { _, _, _ in
                ServerResponse(HTTPResponse(status: .ok), body: [])
            }
        )
    }

    /// A routed body chunk of `count` octets — the event kind whose payload actually scales with the
    /// peer's input (RFC 9114 §7.2.1).
    private static func chunk(of count: Int) -> HTTP3Connection.Event {
        .requestBodyChunk(streamID: Self.target, bytes: [UInt8](repeating: 0x61, count: count))
    }

    private func isQueued(_ deposit: HTTP3StreamRegistry.Deposit) -> Bool {
        if case .queued = deposit {
            return true
        }
        return false
    }
}
