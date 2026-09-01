//
//  ContentCodingSession.swift
//  HTTPServer
//
//  One response's live content coding (RFC 9110 §8.4.1), made safe to hand to the task that produces
//  the body. A ``ContentEncoderStream`` is stateful and not `Sendable` by design, but a
//  ``ResponseStream``'s producer closure is `@Sendable`, so the codec cannot simply be captured: it has
//  to be owned by something that states its own isolation. That is this type, and the ownership is a
//  `Mutex` rather than an actor because coding a chunk is synchronous CPU work — an actor hop per chunk
//  would buy nothing and cost a suspension on the body path.
//
//  It also makes release deterministic. `release()` drops the codec whether or not the body ever
//  finished, so a client that disconnects mid-download frees the encoder's allocation at that moment
//  rather than whenever the last reference to the producer closure happens to go.
//

internal import Synchronization

/// One response's encoder stream — owned, serialized, and releasable independently of the body's fate.
final class ContentCodingSession: Sendable {
    /// The codec, or nil once finished or released; nil is the terminal state either way.
    private let encoder: Mutex<(any ContentEncoderStream)?>

    /// Takes ownership of `encoder` for the life of one response body.
    init(_ encoder: sending any ContentEncoderStream) {
        self.encoder = Mutex(encoder)
    }

    deinit {
        // The codec is the Mutex's to release; its own `deinit` frees the backend allocation.
    }

    /// Codes one body chunk, or throws if the coding has already ended.
    func update(_ chunk: [UInt8]) throws(ContentEncodingError) -> [UInt8] {
        try encoder.withLock { held throws(ContentEncodingError) in
            guard let held else {
                throw .streamFinished
            }
            return try held.update(chunk)
        }
    }

    /// Flushes the coding, returns its trailing octets, and releases the codec.
    ///
    /// The codec is dropped from the box *before* it is flushed, so a backend error on the last block
    /// still leaves nothing retained.
    func finish() throws(ContentEncodingError) -> [UInt8] {
        try encoder.withLock { held throws(ContentEncodingError) in
            guard let coder = held else {
                throw .streamFinished
            }
            held = nil
            return try coder.finish()
        }
    }

    /// Drops the codec without flushing — the cancellation path.
    ///
    /// Idempotent, and correct to call after ``finish()``: what is on the wire is already a truncated
    /// coded stream, so there is nothing to salvage by flushing, and the only thing left worth doing is
    /// giving the codec's memory back at a point the code names.
    func release() {
        encoder.withLock { $0 = nil }
    }
}
