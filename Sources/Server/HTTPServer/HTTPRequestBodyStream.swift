//
//  HTTPRequestBodyStream.swift
//  HTTPServer
//
//  A back-pressured `AsyncSequence` of request-body chunks — the request-side counterpart of the
//  response's streaming producer (``ResponseStream``). Iterating it yields `[UInt8]` chunks as the
//  engine delivers them and suspends in between, so an arbitrarily large upload is processed with
//  bounded memory. A body may be iterated once.
//
//  Three backings: a finished/buffered `AsyncStream` (the HTTP/1.1 reader and the buffered-to-stream
//  adapter); a single-slot ``AsyncHandoff`` whose producer suspends until the handler takes each chunk —
//  the 1-chunk backpressure behind HTTP/3 wire streaming; or a ``BoundedByteChannel`` paired with an
//  ``HTTP2ConsumptionSignal``, which is HTTP/2's (2026-07-31 audit F4, ADR 0006).
//
//  HTTP/2 needs the third because its producer is the shared multiplexed serve loop, which may never
//  suspend on a handler: the backpressure cannot be "the producer waits", it has to be "the peer is not
//  given more window". So taking a chunk here reports its size through the signal, the serve loop drains
//  that report, and the WINDOW_UPDATE it then issues is what lets the peer send more. Consumption is
//  recorded when the handler TAKES a chunk, not when one is queued — crediting on arrival is exactly the
//  defect being fixed.
//

/// A back-pressured `AsyncSequence` of request-body chunks (the request-side ``ResponseStream`` peer).
public struct HTTPRequestBodyStream: AsyncSequence, Sendable {
    /// One decoded body chunk.
    public typealias Element = [UInt8]

    /// Where the chunks come from: a buffered/finished `AsyncStream`, a back-pressured ``AsyncHandoff``,
    /// or a consumption-gated ``BoundedByteChannel`` reporting through an ``HTTP2ConsumptionSignal``.
    enum Backing: Sendable {
        case stream(AsyncStream<[UInt8]>)
        case handoff(AsyncHandoff)
        case channel(BoundedByteChannel, HTTP2ConsumptionSignal)
    }

    /// An iterator's live source — ``Backing`` advanced to its *iterator* (kept at this level so the
    /// iterator type stays shallow).
    enum IteratorSource {
        case stream(AsyncStream<[UInt8]>.Iterator)
        case handoff(AsyncHandoff)
        case channel(BoundedByteChannel, HTTP2ConsumptionSignal)
    }

    private let backing: Backing

    /// Wraps an `AsyncStream` of chunks — the bridge the HTTP/1.1 reader uses to feed decoded body frames.
    public init(_ base: AsyncStream<[UInt8]>) {
        backing = .stream(base)
    }

    /// A finished stream that yields `bytes` once (when non-empty) — the buffered-to-stream adapter
    /// behind ``RequestBody/asStream``.
    init(yielding bytes: [UInt8]) {
        self.init(
            AsyncStream { continuation in
                if !bytes.isEmpty {
                    continuation.yield(bytes)
                }
                continuation.finish()
            }
        )
    }

    /// Streams chunks pulled from a back-pressured ``AsyncHandoff`` — the engines' true-streaming bridge:
    /// the serve loop offers each decoded body frame and suspends until the handler takes it.
    init(handoff: AsyncHandoff) {
        backing = .handoff(handoff)
    }

    /// Streams chunks from a consumption-gated ``BoundedByteChannel`` — HTTP/2's true-streaming bridge.
    ///
    /// Taking a chunk reports its size through `signal`; the serve loop drains that report and issues
    /// the WINDOW_UPDATE, so the peer is allowed to send exactly as much more as this handler has taken
    /// (RFC 9113 §6.9, ADR 0006).
    init(channel: BoundedByteChannel, signal: HTTP2ConsumptionSignal) {
        backing = .channel(channel, signal)
    }

    /// Returns an iterator that yields each body chunk as the engine delivers it.
    public func makeAsyncIterator() -> Iterator {
        switch backing {
            case .stream(let base):
                return Iterator(source: .stream(base.makeAsyncIterator()))
            case .handoff(let handoff):
                return Iterator(source: .handoff(handoff))
            case .channel(let channel, let signal):
                return Iterator(source: .channel(channel, signal))
        }
    }

    /// The body stream's iterator, over either backing.
    public struct Iterator: AsyncIteratorProtocol {
        var source: IteratorSource

        /// The next body chunk, or `nil` once the body ends — normally, or early on truncation / reset.
        public mutating func next() async -> [UInt8]? {
            switch source {
                case .stream(var iterator):
                    let value = await iterator.next()
                    source = .stream(iterator)
                    return value
                case .handoff(let handoff):
                    switch await handoff.next() {
                        case .chunk(let bytes):
                            return bytes
                        case .finished, .failed:
                            return nil
                    }
                case .channel(let channel, let signal):
                    switch await channel.next() {
                        case .chunk(let bytes):
                            // Report AFTER the take: this is what re-opens the peer's window, and the
                            // whole point of the gate is that it turns on the handler, not on arrival.
                            signal.record(bytes.count)
                            return bytes
                        case .finished, .aborted:
                            return nil
                    }
            }
        }
    }
}
