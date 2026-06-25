//
//  ResponseStream.swift
//  HTTPServer
//
//  An incremental response body: a producer the serving engine drives, pushing chunks to a
//  ``ResponseBodyWriter`` as they are ready (chunked downloads, Server-Sent Events, generated bodies).
//  HTTP/1.1 streams it natively (chunked transfer-coding, or a fixed Content-Length when known); engines
//  without native streaming yet collapse a finite stream into one buffer (``collect(maxBytes:)``).
//

internal import Synchronization

/// An incremental response body — a producer the engine pumps to the wire (RFC 9112 §7.1 chunked).
public struct ResponseStream: Sendable {
    /// The body length when known ahead of time; nil streams with chunked framing (HTTP/1.1) instead.
    public let contentLength: Int?
    let produce: @Sendable (any ResponseBodyWriter) async throws -> Void

    /// Creates a stream that writes its body through the producer; pass `contentLength` when known.
    public init(
        contentLength: Int? = nil,
        _ produce: @escaping @Sendable (any ResponseBodyWriter) async throws -> Void
    ) {
        self.contentLength = contentLength
        self.produce = produce
    }

    /// Runs the producer into one buffer — the fallback for engines without native streaming yet.
    ///
    /// Returns nil if the body would exceed `maxBytes` or the producer throws, so a stream too large to
    /// buffer (or an unbounded one) fails rather than being silently truncated.
    func collect(maxBytes: Int) async -> [UInt8]? {
        let writer = CollectingWriter(cap: maxBytes)
        do {
            try await produce(writer)
        }
        catch {
            return nil
        }
        return writer.bytes
    }

    /// A ``ResponseBodyWriter`` that accumulates chunks into a capped buffer (the buffering fallback).
    private final class CollectingWriter: ResponseBodyWriter, Sendable {
        private let buffer = Mutex<[UInt8]>([])
        private let cap: Int

        init(cap: Int) {
            self.cap = cap
        }

        deinit {
            // No teardown beyond ARC; the Mutex releases with the instance.
        }

        var bytes: [UInt8] {
            buffer.withLock(\.self)
        }

        func write(_ chunk: [UInt8]) async throws {
            try buffer.withLock { stored in
                guard stored.count + chunk.count <= cap else {
                    throw CollectError.tooLarge
                }
                stored.append(contentsOf: chunk)
            }
        }
    }

    /// Signals that a buffered stream exceeded the byte cap (caught by ``collect(maxBytes:)``).
    private enum CollectError: Error {
        case tooLarge
    }
}
