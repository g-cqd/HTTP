//
//  BoundedByteChannelTests.swift
//  HTTPServerTests
//
//  The lossless, byte-watermarked transport→application FIFO behind HTTP/1.1 WebSocket intake and
//  the HTTP/2 raw mailbox (2026-07-31 audit, findings 1–4). The properties under test are the ones
//  the audit demands and the old `.bufferingNewest(256)` / `.unbounded` streams did not have:
//  nothing is ever dropped, the producer parks at a *byte* watermark and resumes with hysteresis,
//  the hard chunk cap bounds the mailbox ticket count, and cancelling either party resumes it rather
//  than leaking a continuation.
//

import Testing

@testable import HTTPServer

@Suite("HTTPServer — BoundedByteChannel (lossless byte-watermarked handoff)")
struct BoundedByteChannelTests {
    private func channel(
        high: Int = 1_024, low: Int = 512, chunks: Int = 8, coalescing: Int = 0
    ) -> BoundedByteChannel {
        BoundedByteChannel(
            highWatermark: high,
            lowWatermark: low,
            maxQueuedChunks: chunks,
            coalescingBelow: coalescing
        )
    }

    /// Transport octets are lossless even when the consumer is far slower than the producer.
    ///
    /// A chunk count far above every watermark proves the producer parked rather than dropping.
    @Test("every chunk arrives, in order, across many watermark crossings")
    func deliversEveryChunkInOrder() async {
        let channel = channel(chunks: 16)
        let expected = (0 ..< 200).map { [UInt8($0 % 251), UInt8(($0 / 251) % 251)] }
        let producer = Task {
            for chunk in expected {
                await channel.send(chunk)
            }
            await channel.finish()
        }
        var received: [[UInt8]] = []
        while case .chunk(let bytes) = await channel.next() {
            received.append(bytes)
        }
        await producer.value
        #expect(received == expected)
    }

    /// The queue is bounded by the watermark plus at most the one chunk that crossed it.
    ///
    /// Sampling after each take is a valid observation — the actor serializes it against every send.
    @Test(
        "queued bytes never exceed the high watermark plus one chunk",
        arguments: [(256, 128, 32), (1_024, 512, 200), (64, 0, 16)]
    )
    func parksAtTheHighWatermark(high: Int, low: Int, chunkSize: Int) async {
        let channel = channel(high: high, low: low, chunks: 64)
        let chunk = [UInt8](repeating: 0xAB, count: chunkSize)
        let producer = Task {
            for _ in 0 ..< 100 {
                await channel.send(chunk)
            }
            await channel.finish()
        }
        var taken = 0
        while case .chunk = await channel.next() {
            taken += 1
            #expect(await channel.queuedBytes <= high + chunkSize)
            #expect(await channel.queuedChunks <= 64)
        }
        await producer.value
        #expect(taken == 100)
    }

    /// `trySend` is the discipline for a producer that must never suspend (the HTTP/2 serve loop).
    ///
    /// It fails *closed* — the caller escalates to RST_STREAM — and never silently drops.
    @Test("trySend refuses at the hard chunk cap rather than dropping")
    func trySendRefusesAtTheChunkCap() async {
        let channel = channel(high: 1 << 20, low: 1 << 19, chunks: 4)
        for _ in 0 ..< 4 {
            #expect(await channel.trySend([1]) == .queued)
        }
        #expect(await channel.trySend([1]) == .refused)
        _ = await channel.next()
        #expect(await channel.trySend([1]) == .queued)  // a take frees exactly one slot
    }

    @Test("trySend refuses at the byte watermark but always accepts into an empty queue")
    func trySendRefusesAtTheByteWatermark() async {
        let channel = channel(high: 64, low: 32, chunks: 64)
        // Oversized, but the queue is empty — an empty channel always accepts, whatever the chunk size.
        #expect(await channel.trySend([UInt8](repeating: 0, count: 4_096)) == .queued)
        #expect(await channel.trySend([1]) == .refused)  // now over the watermark
    }

    @Test("finish is delivered only after every already-queued chunk")
    func finishDrainsQueuedChunksFirst() async {
        let channel = channel()
        await channel.send([1])
        await channel.send([2])
        await channel.finish()
        #expect(await channel.next() == .chunk([1]))
        #expect(await channel.next() == .chunk([2]))
        #expect(await channel.next() == .finished)
        #expect(await channel.next() == .finished)  // terminal is sticky
    }

    @Test("abandon discards the queue and reports aborted")
    func abandonDiscardsTheQueue() async {
        let channel = channel()
        await channel.send([1])
        await channel.abandon()
        #expect(await channel.next() == .aborted)
        #expect(await channel.queuedBytes == 0)
    }

    /// Teardown must not leak a checked continuation.
    ///
    /// The connection's `defer` abandons the channel while the reader is parked in `send`, and the
    /// reader has to unwind for the serve task to exit.
    @Test("abandon unblocks a producer parked above the watermark")
    func abandonUnblocksParkedProducer() async {
        let channel = channel(high: 4, low: 2, chunks: 2)
        let producer = Task {
            await channel.send([1, 2, 3, 4])
            await channel.send([5, 6, 7, 8])  // parks: over both watermarks
            await channel.send([9])
        }
        await Task.yield()
        await channel.abandon()
        await producer.value  // completes rather than hanging
        #expect(await channel.next() == .aborted)
    }

    @Test("a consumer parked in next resumes aborted when its task is cancelled")
    func cancelledConsumerResumes() async {
        let channel = channel()
        let consumer = Task { await channel.next() }
        await Task.yield()
        consumer.cancel()
        #expect(await consumer.value == .aborted)
    }

    @Test("a producer parked in send returns when its task is cancelled")
    func cancelledProducerResumes() async {
        let channel = channel(high: 4, low: 2, chunks: 2)
        let producer = Task {
            await channel.send([1, 2, 3, 4])
            await channel.send([5, 6, 7, 8])  // parks
        }
        await Task.yield()
        producer.cancel()
        await producer.value  // completes rather than hanging
    }

    @Test("a consumer parked before any send wakes on the first chunk")
    func parkedConsumerWakesOnSend() async {
        let channel = channel()
        let consumer = Task { await channel.next() }
        await Task.yield()
        await channel.send([42])
        #expect(await consumer.value == .chunk([42]))
    }

    /// Coalescing keeps a peer dribbling one-octet frames from inflating the chunk count.
    ///
    /// It is opt-in: the byte stream is unchanged, only the chunk boundaries are, which is safe for a
    /// resumable parser and a request body but not for a caller that treats a chunk as a message.
    @Test("coalescing merges into a small tail chunk without changing the byte stream")
    func coalescesSmallTailChunks() async {
        let channel = channel(chunks: 4, coalescing: 64)
        // The first send queues a NEW item; every later one merges into it. That distinction is
        // load-bearing for a *ticketed* caller (the HTTP/2 and WebSocket readers): a ticket is owed only
        // for a new item, and yielding one for a merge would leave the consumer a ticket ahead of the
        // queue and park it in `next()` — hanging the whole merged mailbox, not just this stream.
        #expect(await channel.trySend([1]) == .queued)
        for byte in UInt8(2) ... 8 {
            #expect(await channel.trySend([byte]) == .coalesced)  // no ticket owed
        }
        #expect(await channel.queuedChunks == 1)
        #expect(await channel.next() == .chunk([1, 2, 3, 4, 5, 6, 7, 8]))
    }

    /// The regression for the ticket/coalescing mismatch (2026-07-31 audit follow-up).
    ///
    /// A ticketed producer that yielded one ticket per `send` — not per queued item — put the consumer
    /// permanently ahead of the queue the moment two sends coalesced. `next()` then suspended, which for
    /// a merged-mailbox consumer means it stops applying *every* wakeup kind: no responses, no tunnel
    /// traffic, and in particular no consumption reports, so a peer stalled on a closed flow-control
    /// window never gets it back and the connection hangs until the idle timeout.
    @Test("one ticket per queued item survives coalescing — the consumer never runs ahead")
    func ticketsMatchQueuedItemsUnderCoalescing() async {
        let channel = channel(chunks: 8, coalescing: 4_096)
        // A small chunk followed by a large one is the exact shape the HTTP/2 reader produces: a short
        // preface/headers read, then a full-size body read landing while the first is still queued.
        let head = [UInt8](repeating: 1, count: 60)
        let tail = [UInt8](repeating: 2, count: 16_384)
        var tickets = 0
        for chunk in [head, tail] where await channel.send(chunk) == .queued {
            tickets += 1
        }
        #expect(tickets == 1)
        #expect(await channel.queuedChunks == 1)
        // Every ticket is redeemable without suspending: exactly `tickets` items are waiting.
        #expect(await channel.next() == .chunk(head + tail))
    }

    @Test("sending after finish is a no-op rather than a trap")
    func sendAfterFinishIsInert() async {
        let channel = channel()
        await channel.finish()
        await channel.send([1])
        #expect(await channel.trySend([1]) == .refused)
        #expect(await channel.next() == .finished)
    }
}
