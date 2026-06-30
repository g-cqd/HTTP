//
//  HTTPRequestBodyStream.swift
//  HTTPServer
//
//  A back-pressured `AsyncSequence` of request-body chunks — the request-side counterpart of the
//  response's streaming producer (``ResponseStream``). Iterating it yields `[UInt8]` chunks as the
//  engine delivers them and suspends in between, so an arbitrarily large upload is processed with
//  bounded memory. A body may be iterated once.
//

/// A back-pressured `AsyncSequence` of request-body chunks (the request-side ``ResponseStream`` peer).
public struct HTTPRequestBodyStream: AsyncSequence, Sendable {
    /// One decoded body chunk.
    public typealias Element = [UInt8]

    private let base: AsyncStream<[UInt8]>

    /// Wraps an `AsyncStream` of chunks — the bridge the engines use to feed decoded body frames in.
    public init(_ base: AsyncStream<[UInt8]>) {
        self.base = base
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

    /// Returns an iterator that yields each body chunk as the engine delivers it.
    public func makeAsyncIterator() -> AsyncStream<[UInt8]>.Iterator {
        base.makeAsyncIterator()
    }
}
