//
//  AsyncHandoff.swift
//  HTTPServer
//
//  A single-slot async rendezvous bridging a push-based ``ResponseStream`` producer to the pull-based
//  HTTP/2 serve loop. The producer `offer`s body chunks and suspends until the loop `next`s each one, so
//  at most one chunk is ever in flight — the backpressure that keeps native streaming bounded. The loop
//  consumes `.chunk` / `.finished` / `.failed` items. `finish`/`fail` terminate it, resuming any party
//  parked on a continuation so cancelling the connection never leaks a checked continuation.
//
//  One producer + one consumer (the streaming stream's producer task and its serve loop) — not a general
//  multi-party channel.
//

/// A one-slot async handoff from a streaming producer to the HTTP/2 serve loop (1-chunk backpressure).
actor AsyncHandoff {
    /// What the consuming loop pulls next.
    enum Item: Sendable, Equatable {
        case chunk([UInt8])
        case finished
        case failed
    }

    private var pending: [UInt8]?
    private var closed: Item?
    private var producerWaiter: CheckedContinuation<Void, Never>?
    private var consumerWaiter: CheckedContinuation<Item, Never>?

    /// Producer: offer a body chunk, suspending until the consumer takes it (or the handoff closes).
    func offer(_ chunk: [UInt8]) async {
        while pending != nil, closed == nil {
            await withCheckedContinuation { producerWaiter = $0 }
        }
        guard closed == nil else {
            return  // the consumer is gone — drop the chunk
        }
        if let consumer = consumerWaiter {
            consumerWaiter = nil
            consumer.resume(returning: .chunk(chunk))
        }
        else {
            pending = chunk
        }
    }

    /// Producer: signal that the body completed normally.
    func finish() {
        close(.finished)
    }

    /// Producer: signal that the body producer threw.
    func fail() {
        close(.failed)
    }

    /// Consumer: signal that the consumer is gone — the request-body handler returned without draining
    /// the stream — so a producer parked on ``offer(_:)`` resumes at once and further offers drop.
    ///
    /// The request-direction abandon path (the response-direction producer uses ``finish()`` / ``fail()``).
    func abandon() {
        close(.failed)
    }

    /// Consumer: take the next item — a buffered chunk, then the terminal state once the producer ends.
    ///
    /// Cancellation-aware (FIX #1): if the consuming serve task is cancelled while parked here — the
    /// idle watchdog reaping the connection because the producer wedged and offered no chunk within a
    /// deadline window — this resumes `.failed` instead of staying parked forever, so the pump unwinds
    /// and the connection actually closes. The pre-park cancellation re-check plus the nil-out on resume
    /// keep the continuation resumed exactly once whether the producer, `close`, or the cancel wins.
    func next() async -> Item {
        if let chunk = pending {
            pending = nil
            if let producer = producerWaiter {
                producerWaiter = nil
                producer.resume()
            }
            return .chunk(chunk)
        }
        if let closed {
            return closed
        }
        return await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<Item, Never>) in
                if let closed {
                    continuation.resume(returning: closed)  // producer ended between the check and here
                }
                else if Task.isCancelled {
                    continuation.resume(returning: .failed)  // already cancelled before we parked
                }
                else {
                    consumerWaiter = continuation
                }
            }
        } onCancel: {
            Task { await self.resumeConsumerOnCancel() }
        }
    }

    /// Resumes a consumer parked in ``next()`` with `.failed` when its task is cancelled (FIX #1).
    ///
    /// A no-op once the producer or ``close(_:)`` has already taken the waiter — actor isolation
    /// serializes this against them, and the nil-out guarantees a single resume.
    private func resumeConsumerOnCancel() {
        guard closed == nil, let consumer = consumerWaiter else {
            return
        }
        consumerWaiter = nil
        consumer.resume(returning: .failed)
    }

    /// Terminates the handoff, resuming both parked parties so no continuation leaks (RFC-agnostic).
    private func close(_ item: Item) {
        let terminal = closed ?? item
        closed = terminal
        if let consumer = consumerWaiter {
            consumerWaiter = nil
            consumer.resume(returning: terminal)
        }
        if let producer = producerWaiter {
            producerWaiter = nil
            producer.resume()
        }
    }
}
