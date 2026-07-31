//
//  PullBodyProducer.swift
//  HTTPServerTests
//
//  A request-body producer that hands out one chunk per consumer pull and records how many it handed
//  out — the instrument behind every "this middleware did not buffer the body" assertion. Backed by
//  `AsyncStream(unfolding:)`, which never runs ahead of the consumer, so `pulled` is exactly what the
//  consumer took: a middleware that calls `collect()` drains the producer to the end, while one that
//  forwards chunks leaves it partly (or wholly) undrained.
//

@testable import HTTPServer

/// A pull-based ``RequestBody`` source that records how much of itself the consumer actually took.
actor PullBodyProducer {
    private let chunks: [[UInt8]]
    private var handedOut = 0

    /// Creates a producer that yields `chunks` in order, one per pull.
    init(_ chunks: [[UInt8]]) {
        self.chunks = chunks
    }

    /// Creates a producer that yields `count` chunks of `size` octets, each filled with its own index.
    init(chunkCount count: Int, size: Int) {
        chunks = (0 ..< count)
            .map { index in
                [UInt8](repeating: UInt8(truncatingIfNeeded: index), count: size)
            }
    }

    /// How many chunks the consumer has pulled so far.
    var pulled: Int { handedOut }

    /// Whether every chunk was handed out — true exactly when the consumer drained the whole body.
    var isDrained: Bool { handedOut >= chunks.count }

    /// Every chunk concatenated: what a complete, unbounded collect would return.
    nonisolated var allBytes: [UInt8] { chunks.flatMap(\.self) }

    /// A streaming ``RequestBody`` drawing from this producer.
    nonisolated func makeBody() -> RequestBody {
        let produce: @Sendable () async -> [UInt8]? = { await self.next() }
        return .stream(HTTPRequestBodyStream(AsyncStream(unfolding: produce)))
    }

    /// The next chunk, or nil once every chunk has been handed out.
    private func next() -> [UInt8]? {
        guard handedOut < chunks.count else {
            return nil
        }
        defer { handedOut += 1 }
        return chunks[handedOut]
    }
}
