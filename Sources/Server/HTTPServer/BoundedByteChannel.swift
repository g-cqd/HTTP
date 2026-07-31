//
//  BoundedByteChannel.swift
//  HTTPServer
//
//  A lossless, byte-watermarked FIFO from one transport/protocol producer to one application
//  consumer.
//
//  The 2026-07-31 audit (findings 1–4) found the same defect in four places: a queue between a
//  transport producer and an application consumer whose depth is not a function of anything the
//  application does. Two spellings of that bug appeared — `.bufferingNewest(256)`, which *discards*
//  transport octets and so desynchronizes a resumable frame parser, and `.unbounded`, which lets a
//  conforming peer grow the server's memory without limit. This type replaces both.
//
//  Discipline:
//    • Nothing is ever discarded. `send(_:)` parks the producer; `trySend(_:)` returns `.refused` and
//      the caller escalates (RST_STREAM / close). A drop policy is never valid for transport octets.
//    • The bound is in *bytes*, not chunks — a count of chunks does not bound retained memory. The
//      chunk cap is a second, independent bound on the mailbox ticket count (see below).
//    • Hysteresis: park at `highWatermark`, resume at `lowWatermark`. Without it a consumer that is
//      only marginally behind would wake the producer once per take.
//
//  Ticket pattern. Where a consumer must merge transport octets with other event kinds through a
//  single sequential `for await`, the payload moves into this channel and the mailbox keeps a
//  payload-free ticket (`.inboundReady`). The producer sends and yields one ticket **only when the
//  send reports `.queued`** — i.e. only when the number of dequeueable items actually rose; a send
//  that coalesced into the tail produced no new item and owes no ticket. That is what keeps `next()`
//  from ever suspending, and it is not a detail: over-ticketing parks the sole consumer on a
//  non-existent item and stalls every other wakeup kind with it. The mailbox `AsyncStream` may then
//  stay `.unbounded` because it is *provably* bounded: inbound tickets can never exceed
//  `maxQueuedChunks`, since the producer is parked past that point.
//
//  Sibling of `AsyncHandoff`, not a generalization of it. `AsyncHandoff` is a zero-queue rendezvous,
//  and its "at most one chunk is ever in flight" property is load-bearing for `HTTP2StreamPermit`.
//  Only the exactly-once continuation discipline is shared, and it is copied rather than inherited.
//
//  One producer + one consumer. Not a multi-party channel.
//

/// A lossless, byte-watermarked FIFO from a transport producer to an application consumer.
actor BoundedByteChannel {
    /// What the consuming loop pulls next.
    enum Item: Sendable, Equatable {
        case chunk([UInt8])
        /// The producer ended normally (EOF / END_STREAM).
        ///
        /// Delivered only after every already-queued chunk.
        case finished
        /// The stream was reset, or the consumer abandoned it.
        ///
        /// Any queued chunks are discarded.
        case aborted
    }

    /// What a send did, and therefore whether the caller owes a wakeup ticket.
    ///
    /// The ticket protocol's whole correctness rests on this: a merged consumer mailbox carries one
    /// payload-free ticket per *dequeueable item*, and the consumer calls `next()` exactly once per
    /// ticket. If a send that produced no new item still made the caller emit a ticket, that ticket
    /// would send the sole consumer into `next()` with nothing to take — parking it, and with it every
    /// other wakeup kind (responses, broadcasts, tunnel output) until unrelated traffic happened to
    /// arrive. That is a connection-level stall, so the accounting cannot be left to the call site's
    /// good intentions.
    enum Acceptance: Sendable, Equatable {
        /// A new item is queued; the caller MUST emit exactly one ticket for it.
        case queued
        /// The octets were absorbed into an item that already has a ticket outstanding — merged into
        /// the tail, or handed straight to a parked consumer. The caller MUST NOT emit a ticket.
        case absorbed
        /// Nothing was enqueued: the channel is saturated, closed, or the producer was cancelled. No
        /// ticket is owed. For `trySend` this is the fail-closed signal the caller escalates.
        case refused
    }

    /// Queued octets past which `send(_:)` parks and `trySend(_:)` refuses.
    private let highWatermark: Int
    /// Queued octets at or below which a parked producer resumes.
    private let lowWatermark: Int
    /// The hard cap on queued chunks — bounds the mailbox ticket count as well as the ring.
    private let maxQueuedChunks: Int
    /// Merge into the tail chunk while it is smaller than this.
    ///
    /// Bounds the chunk count when a peer dribbles one-octet frames. Zero disables it. Only callers
    /// whose consumer treats the stream as octets (a resumable parser, a request body) may enable
    /// it — never one that treats a chunk as a message.
    private let coalescingBelow: Int

    private var ring: ContiguousArray<[UInt8]?>
    private var head = 0
    private var queued = 0
    private var bytes = 0
    private var terminal: Item?

    private var producerWaiter: CheckedContinuation<Void, Never>?
    private var consumerWaiter: CheckedContinuation<Item, Never>?

    /// Creates a channel bounded by both a byte watermark pair and a hard chunk cap.
    ///
    /// - Parameters:
    ///   - highWatermark: queued octets past which the producer parks. Clamped to at least 1.
    ///   - lowWatermark: queued octets at or below which it resumes. Clamped below `highWatermark`.
    ///   - maxQueuedChunks: the hard chunk cap. Clamped to at least 1.
    ///   - coalescingBelow: merge into a tail chunk smaller than this; 0 disables.
    init(highWatermark: Int, lowWatermark: Int, maxQueuedChunks: Int, coalescingBelow: Int = 0) {
        let high = max(1, highWatermark)
        self.highWatermark = high
        self.lowWatermark = min(max(0, lowWatermark), high - 1)
        let chunks = max(1, maxQueuedChunks)
        self.maxQueuedChunks = chunks
        self.coalescingBelow = max(0, coalescingBelow)
        ring = ContiguousArray(repeating: nil, count: chunks)
    }

    // MARK: - Observability

    /// Unconsumed octets held by the channel — the memory bound, for tests and metrics.
    var queuedBytes: Int { bytes }

    /// Unconsumed chunks held by the channel — bounds the consumer's outstanding ticket count.
    var queuedChunks: Int { queued }

    // MARK: - Producer

    /// Sends `chunk`, suspending while the channel is saturated.
    ///
    /// Never discards. Suspending here *is* the backpressure: a reader task parked in `send` is not
    /// calling `connection.receive`, so the kernel receive buffer fills and the peer's TCP window
    /// closes.
    ///
    /// Cancellation-aware. If the producing task is cancelled while parked — the connection is being
    /// reaped — this returns without enqueuing. That is a deliberate loss on a path where the
    /// connection is going away regardless; a *live* connection never loses an octet.
    ///
    /// - Returns: whether the caller owes a wakeup ticket. See ``Acceptance``.
    @discardableResult
    func send(_ chunk: [UInt8]) async -> Acceptance {
        guard !chunk.isEmpty else {
            return .refused
        }
        while terminal == nil, !Task.isCancelled, isSaturated {
            await parkProducer()
        }
        guard terminal == nil, !Task.isCancelled else {
            return .refused
        }
        return enqueue(chunk)
    }

    /// Sends `chunk` without ever suspending, for a producer that must not park.
    ///
    /// The HTTP/2 serve loop is the sole owner of the connection engine and cannot block on
    /// application progress, so it uses this rather than `send(_:)`.
    ///
    /// - Returns: `.refused` when the channel is saturated or closed. That is a *hard error* the caller
    ///   escalates (RST_STREAM / close), never a silent drop. On a consumption-gated stream it is
    ///   unreachable in practice — the flow-control window already bounds what the peer may send — so
    ///   it stands as defense in depth that fails closed. Otherwise, see ``Acceptance`` for whether a
    ///   ticket is owed.
    @discardableResult
    func trySend(_ chunk: [UInt8]) -> Acceptance {
        guard !chunk.isEmpty else {
            return .absorbed
        }
        guard terminal == nil, !isSaturated else {
            return .refused
        }
        return enqueue(chunk)
    }

    /// Ends the stream normally.
    ///
    /// Already-queued chunks are still delivered before `.finished`.
    func finish() {
        close(.finished, discardingQueue: false)
    }

    // MARK: - Consumer

    /// Takes the next item: every queued chunk in order, then the terminal state.
    ///
    /// Cancellation-aware, mirroring `AsyncHandoff.next()`: a consumer parked here when its task is
    /// cancelled resumes `.aborted` rather than staying parked forever, so the connection actually
    /// closes. The pre-park re-check plus the nil-out on resume keep the continuation resumed exactly
    /// once whichever of the producer, `close(_:discardingQueue:)`, or the cancellation wins.
    func next() async -> Item {
        if let chunk = dequeue() {
            return .chunk(chunk)
        }
        if let terminal {
            return terminal
        }
        return await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<Item, Never>) in
                if let chunk = dequeue() {
                    continuation.resume(returning: .chunk(chunk))  // a send landed before we parked
                }
                else if let terminal {
                    continuation.resume(returning: terminal)
                }
                else if Task.isCancelled {
                    continuation.resume(returning: .aborted)  // cancelled before we parked
                }
                else {
                    consumerWaiter = continuation
                }
            }
        } onCancel: {
            Task { await self.resumeConsumerOnCancel() }
        }
    }

    /// Discards the queue and terminates as `.aborted`, resuming both parties.
    ///
    /// The consumer-side teardown: the handler returned without draining the body, or the stream was
    /// reset. A producer parked in `send(_:)` resumes at once, so a connection `defer` can unwind a
    /// wedged reader.
    func abandon() {
        close(.aborted, discardingQueue: true)
    }

    // MARK: - Queue

    private var isSaturated: Bool {
        queued >= maxQueuedChunks || bytes >= highWatermark
    }

    /// Appends `chunk`, handing it straight to a parked consumer when there is one.
    ///
    /// A parked consumer implies an empty queue, so the direct handoff can never skip an ordering.
    ///
    /// - Returns: `.queued` only when the number of dequeueable items actually increased. Both other
    ///   outcomes absorbed the octets into an item that is already accounted for.
    private func enqueue(_ chunk: [UInt8]) -> Acceptance {
        if let consumer = consumerWaiter {
            consumerWaiter = nil
            consumer.resume(returning: .chunk(chunk))
            return .absorbed
        }
        bytes += chunk.count
        if coalesceIntoTail(chunk) {
            return .absorbed
        }
        ring[(head + queued) % ring.count] = chunk
        queued += 1
        return .queued
    }

    /// Merges into the tail chunk while it is below `coalescingBelow`.
    ///
    /// Taking the tail out of the ring before appending drops the ring's reference, so the local is
    /// uniquely referenced and `append` grows in place instead of paying the copy-on-write tax.
    private func coalesceIntoTail(_ chunk: [UInt8]) -> Bool {
        guard coalescingBelow > 0, queued > 0 else {
            return false
        }
        let tail = (head + queued - 1) % ring.count
        guard var existing = ring[tail], existing.count < coalescingBelow else {
            return false
        }
        ring[tail] = nil
        existing.append(contentsOf: chunk)
        ring[tail] = existing
        return true
    }

    private func dequeue() -> [UInt8]? {
        guard queued > 0, let chunk = ring[head] else {
            return nil
        }
        ring[head] = nil
        head = (head + 1) % ring.count
        queued -= 1
        bytes -= chunk.count
        releaseProducerIfDrained()
        return chunk
    }

    /// Resumes a parked producer once the queue has fallen back to `lowWatermark`.
    ///
    /// This is the hysteresis that keeps a marginally-behind consumer from waking the producer on
    /// every single take.
    private func releaseProducerIfDrained() {
        guard let producer = producerWaiter, bytes <= lowWatermark, queued < maxQueuedChunks else {
            return
        }
        producerWaiter = nil
        producer.resume()
    }

    private func parkProducer() async {
        await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                if terminal != nil || Task.isCancelled || !isSaturated {
                    continuation.resume()
                }
                else {
                    producerWaiter = continuation
                }
            }
        } onCancel: {
            Task { await self.resumeProducerOnCancel() }
        }
    }

    private func resumeConsumerOnCancel() {
        guard let consumer = consumerWaiter else {
            return
        }
        consumerWaiter = nil
        consumer.resume(returning: terminal ?? .aborted)
    }

    private func resumeProducerOnCancel() {
        guard let producer = producerWaiter else {
            return
        }
        producerWaiter = nil
        producer.resume()
    }

    /// Terminates the channel, resuming both parked parties so no continuation leaks.
    ///
    /// A parked consumer implies an empty queue (`enqueue(_:)` hands straight to it), so resuming it
    /// with the terminal item can never skip a queued chunk.
    private func close(_ item: Item, discardingQueue: Bool) {
        let settled = terminal ?? item
        terminal = settled
        if discardingQueue {
            ring = ContiguousArray(repeating: nil, count: maxQueuedChunks)
            head = 0
            queued = 0
            bytes = 0
        }
        if let consumer = consumerWaiter {
            consumerWaiter = nil
            consumer.resume(returning: settled)
        }
        if let producer = producerWaiter {
            producerWaiter = nil
            producer.resume()
        }
    }
}
