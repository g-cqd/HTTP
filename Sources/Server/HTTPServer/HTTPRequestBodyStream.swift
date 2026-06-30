//
//  HTTPRequestBodyStream.swift
//  HTTPServer
//
//  A back-pressured `AsyncSequence` of request-body chunks — the request-side counterpart of the
//  response's streaming producer (``ResponseStream``). Iterating it yields `[UInt8]` chunks as the
//  engine delivers them and suspends in between, so an arbitrarily large upload is processed with
//  bounded memory. A body may be iterated once.
//
//  Two backings: a finished/buffered `AsyncStream` (the HTTP/1.1 reader and the buffered-to-stream
//  adapter), or a single-slot ``AsyncHandoff`` whose producer suspends until the handler takes each chunk
//  — the 1-chunk backpressure behind true HTTP/2 + HTTP/3 wire streaming.
//

/// A back-pressured `AsyncSequence` of request-body chunks (the request-side ``ResponseStream`` peer).
public struct HTTPRequestBodyStream: AsyncSequence, Sendable {
    /// One decoded body chunk.
    public typealias Element = [UInt8]

    /// Where the chunks come from: a buffered/finished `AsyncStream`, or a back-pressured ``AsyncHandoff``.
    enum Backing: Sendable {
        case stream(AsyncStream<[UInt8]>)
        case handoff(AsyncHandoff)
    }

    /// An iterator's live source — ``Backing`` advanced to its *iterator* (kept at this level so the
    /// iterator type stays shallow).
    enum IteratorSource {
        case stream(AsyncStream<[UInt8]>.Iterator)
        case handoff(AsyncHandoff)
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

    /// Returns an iterator that yields each body chunk as the engine delivers it.
    public func makeAsyncIterator() -> Iterator {
        switch backing {
            case .stream(let base):
                return Iterator(source: .stream(base.makeAsyncIterator()))
            case .handoff(let handoff):
                return Iterator(source: .handoff(handoff))
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
            }
        }
    }
}
