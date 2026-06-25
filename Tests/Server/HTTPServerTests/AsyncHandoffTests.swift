//
//  AsyncHandoffTests.swift
//  HTTPServerTests
//
//  The one-slot producer→loop rendezvous behind native HTTP/2 streaming: chunks arrive in order then a
//  terminal item; a parked consumer wakes on the first offer; the 1-slot backpressure is exercised by a
//  producer that offers more than one chunk; and `fail` terminates and unblocks both parties (so a
//  cancelled connection never leaks a continuation). Outcomes are deterministic regardless of interleave.
//

import Testing

@testable import HTTPServer

@Suite("HTTPServer — AsyncHandoff (native streaming backpressure bridge)")
struct AsyncHandoffTests {
    @Test("chunks arrive in order, then the terminal item (1-slot backpressure across many chunks)")
    func deliversInOrderThenFinished() async {
        let handoff = AsyncHandoff()
        let producer = Task {
            for byte in UInt8(0) ..< 8 {
                await handoff.offer([byte])  // offers past slot 1 park until the consumer pulls
            }
            await handoff.finish()
        }
        var received: [AsyncHandoff.Item] = []
        while true {
            let item = await handoff.next()
            received.append(item)
            if item == .finished || item == .failed { break }
        }
        await producer.value
        let expected =
            (UInt8(0) ..< 8).map { AsyncHandoff.Item.chunk([$0]) } + [.finished]
        #expect(received == expected)
    }

    @Test("a consumer parked before any offer wakes on the first chunk")
    func consumerParksThenWakes() async {
        let handoff = AsyncHandoff()
        let consumer = Task { await handoff.next() }
        await Task.yield()
        await handoff.offer([42])
        #expect(await consumer.value == .chunk([42]))
    }

    @Test("finish drains a still-pending chunk before reporting the terminal item")
    func finishDrainsPending() async {
        let handoff = AsyncHandoff()
        await handoff.offer([1])  // stored in the slot (no consumer waiting → no suspension)
        await handoff.finish()
        #expect(await handoff.next() == .chunk([1]))  // pending drains first
        #expect(await handoff.next() == .finished)
    }

    @Test("fail terminates the handoff and unblocks a producer parked on a full slot")
    func failUnblocksParkedProducer() async {
        let handoff = AsyncHandoff()
        let producer = Task {
            await handoff.offer([1])  // fills the slot
            await handoff.offer([2])  // parks (slot full)
            await handoff.offer([3])  // returns immediately once closed
        }
        await Task.yield()
        await handoff.fail()
        await producer.value  // must complete — proves no deadlock / continuation leak
        #expect(await handoff.next() == .chunk([1]))  // the stored chunk still drains
        #expect(await handoff.next() == .failed)
    }
}
