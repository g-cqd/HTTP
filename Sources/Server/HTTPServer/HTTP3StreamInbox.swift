//
//  HTTP3StreamInbox.swift
//  HTTPServer
//
//  The merged wakeup mailbox of ONE HTTP/3 request stream (audit REG-2). A stream's serve loop has two
//  independent sources of work and must wait on BOTH at once:
//
//    • its own inbound QUIC octets, and
//    • routed engine events another stream's task produced for it — RFC 9204 §2.1.2, where an
//      encoder-stream insert unblocks a field section belonging to a *request* stream.
//
//  Before this type the loop awaited only `stream.receive()` and drained the routed mailbox afterwards,
//  so an unblocked stream with `fin:false` and no further request bytes was never woken at all: the
//  event was deposited and the owner stayed parked until its read deadline reset the stream.
//
//  Shape: a reader task owns `stream.receive()` and `offer`s each chunk here, parking while the loop
//  still holds the previous one — ONE chunk in flight, so the loop's pace is the reader's pace and QUIC
//  flow control back-pressures the peer in turn. The routed side carries no payload: the events live in
//  ``HTTP3StreamRegistry``'s per-stream mailbox and ``signalRouted()`` only says "there is mail". That
//  keeps this type's memory a single chunk plus one flag, whatever the peer does.
//
//  `Mutex` rather than `actor` because ``HTTP3StreamRegistry/deposit(_:for:)`` is synchronous by design
//  (a stream task consults it between two engine calls without an isolation hop) and must be able to
//  wake the owner from inside that call. Every continuation is resumed *outside* the lock, and the
//  nil-out on resume keeps each one resumed exactly once whichever of the producer, the consumer, the
//  close, or a cancellation wins — the discipline copied from ``AsyncHandoff`` and ``BoundedByteChannel``.
//
//  One producer (the stream's reader task) + one consumer (its serve loop). Not a multi-party channel.
//

internal import Synchronization

/// One HTTP/3 request stream's merged mailbox: inbound QUIC chunks plus routed-event wakeups.
final class HTTP3StreamInbox: Sendable {
    /// What a stream's serve loop wakes for.
    enum Wakeup: Sendable, Equatable {
        /// Inbound octets for this stream, carrying QUIC's FIN flag (RFC 9000 §2).
        case inbound(bytes: [UInt8], fin: Bool)
        /// This stream's registry mailbox holds routed engine events (RFC 9204 §2.1.2).
        ///
        /// Payload-free: the consumer drains ``HTTP3StreamRegistry/takeMailbox(_:)``.
        case routed
        /// No more inbound octets will arrive — peer EOF, a receive fault, or teardown.
        case ended
    }

    /// What one ``offer(_:fin:)`` attempt resolved to under the lock.
    private enum OfferStep {
        case queued
        case handoff(CheckedContinuation<Wakeup, Never>)
        case refused
        case park
    }

    /// The inbox contents, plus the two parked parties.
    private struct State {
        var pending: (bytes: [UInt8], fin: Bool)?
        var routedPending = false
        var isEnded = false
        var consumer: CheckedContinuation<Wakeup, Never>?
        var producer: CheckedContinuation<Void, Never>?

        /// Takes the next available wakeup, with the producer to resume once the slot frees up.
        ///
        /// Routed mail comes first: those events were produced by the engine *before* the queued chunk
        /// has been fed to it, so draining them first is the order the engine surfaced them in.
        mutating func take() -> (Wakeup?, CheckedContinuation<Void, Never>?) {
            if routedPending {
                routedPending = false
                return (.routed, nil)
            }
            guard let chunk = pending else {
                return (isEnded ? .ended : nil, nil)
            }
            pending = nil
            let waiting = producer
            producer = nil
            return (.inbound(bytes: chunk.bytes, fin: chunk.fin), waiting)
        }
    }

    private let state = Mutex(State())

    deinit {
        // No teardown beyond ARC; `close()` is what resumes any parked party.
    }

    // MARK: - Observability

    /// Whether the serve loop is parked in ``next()`` — the state a routed deposit must wake.
    var isConsumerParked: Bool {
        state.withLock { $0.consumer != nil }
    }

    /// Whether the reader task is parked in ``offer(_:fin:)`` — the one-chunk backpressure engaged.
    var isProducerParked: Bool {
        state.withLock { $0.producer != nil }
    }

    // MARK: - Producer

    /// Hands one inbound chunk to the serve loop, parking while it still holds the previous one.
    ///
    /// Suspending here *is* the backpressure: a reader parked in `offer` is not calling
    /// `stream.receive()`, so QUIC stops extending the peer's per-stream flow-control window.
    ///
    /// - Returns: `false` once the inbox is closed or the reader is cancelled — the stream is going
    ///   away regardless, and the chunk is dropped.
    func offer(_ bytes: [UInt8], fin: Bool) async -> Bool {
        while true {
            let step = state.withLock { current -> OfferStep in
                guard !current.isEnded, !Task.isCancelled else {
                    return .refused
                }
                guard current.pending == nil else {
                    return .park
                }
                guard let consumer = current.consumer else {
                    current.pending = (bytes, fin)
                    return .queued
                }
                current.consumer = nil
                return .handoff(consumer)
            }
            switch step {
                case .queued:
                    return true
                case .handoff(let consumer):
                    consumer.resume(returning: .inbound(bytes: bytes, fin: fin))
                    return true
                case .refused:
                    return false
                case .park:
                    await parkProducer()
            }
        }
    }

    /// Signals that this stream's registry mailbox holds routed events (RFC 9204 §2.1.2).
    ///
    /// Synchronous and idempotent — many deposits before the loop looks collapse into one wakeup, and
    /// the loop drains the whole mailbox in a single take.
    func signalRouted() {
        let consumer = state.withLock { current -> CheckedContinuation<Wakeup, Never>? in
            guard !current.isEnded else {
                return nil
            }
            guard let waiting = current.consumer else {
                current.routedPending = true
                return nil
            }
            current.consumer = nil
            return waiting
        }
        consumer?.resume(returning: .routed)
    }

    /// Ends the inbox: no further chunk will be offered (peer EOF, a receive fault, teardown).
    ///
    /// Resumes both parked parties so no continuation leaks when a connection is reaped.
    func close() {
        let parked = state.withLock { current -> Parked in
            current.isEnded = true
            let waiting = Parked(consumer: current.consumer, producer: current.producer)
            current.consumer = nil
            current.producer = nil
            return waiting
        }
        parked.consumer?.resume(returning: .ended)
        parked.producer?.resume()
    }

    // MARK: - Consumer

    /// Takes the next wakeup: routed mail first, then the queued chunk, then the end.
    ///
    /// Cancellation-aware: a serve loop parked here when the connection is torn down resumes
    /// ``Wakeup/ended`` rather than staying parked forever, exactly as a loop parked on `receive` is
    /// unwound by the transport going away.
    func next() async -> Wakeup {
        if let ready = takeReady() {
            return ready
        }
        return await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<Wakeup, Never>) in
                if let ready = parkConsumer(continuation) {
                    continuation.resume(returning: ready)
                }
            }
        } onCancel: {
            self.resumeConsumerOnCancel()
        }
    }

    // MARK: - Internals

    /// The parties parked on this inbox at the moment it closed.
    private struct Parked {
        let consumer: CheckedContinuation<Wakeup, Never>?
        let producer: CheckedContinuation<Void, Never>?
    }

    /// Takes a wakeup that is already available, resuming a parked producer when the slot frees up.
    private func takeReady() -> Wakeup? {
        let taken = state.withLock { $0.take() }
        taken.1?.resume()
        return taken.0
    }

    /// Re-checks for a wakeup and otherwise parks `continuation`, returning any immediate result.
    private func parkConsumer(_ continuation: CheckedContinuation<Wakeup, Never>) -> Wakeup? {
        let taken = state.withLock { current -> (Wakeup?, CheckedContinuation<Void, Never>?) in
            // A producer, `signalRouted()`, or `close()` may have landed since `takeReady()`.
            let ready = current.take()
            if ready.0 != nil {
                return ready
            }
            guard !Task.isCancelled else {
                return (.ended, nil)
            }
            current.consumer = continuation
            return (nil, nil)
        }
        taken.1?.resume()
        return taken.0
    }

    /// Resumes a consumer parked in ``next()`` when its task is cancelled.
    private func resumeConsumerOnCancel() {
        let consumer = state.withLock { current -> CheckedContinuation<Wakeup, Never>? in
            let waiting = current.consumer
            current.consumer = nil
            return waiting
        }
        consumer?.resume(returning: .ended)
    }

    /// Parks the producer until the consumer frees the slot, the inbox closes, or the task is cancelled.
    private func parkProducer() async {
        await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                let resumeNow = state.withLock { current -> Bool in
                    guard !current.isEnded, !Task.isCancelled, current.pending != nil else {
                        return true
                    }
                    current.producer = continuation
                    return false
                }
                if resumeNow {
                    continuation.resume()
                }
            }
        } onCancel: {
            self.resumeProducerOnCancel()
        }
    }

    /// Resumes a producer parked in ``parkProducer()`` when its reader task is cancelled.
    private func resumeProducerOnCancel() {
        let producer = state.withLock { current -> CheckedContinuation<Void, Never>? in
            let waiting = current.producer
            current.producer = nil
            return waiting
        }
        producer?.resume()
    }
}
