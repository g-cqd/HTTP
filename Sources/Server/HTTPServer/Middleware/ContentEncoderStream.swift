//
//  ContentEncoderStream.swift
//  HTTPServer
//
//  One incremental content-coding encode (RFC 9110 §8.4.1): the seam that lets a streamed response body
//  be coded without ever being held. ``ContentEncoder`` is one-shot by construction — it takes the whole
//  body and returns the whole coding — which is exactly the retention a streamed body exists to avoid,
//  so streaming needs its own shape rather than a larger buffer.
//
//  A class, not a struct, because the state a real backend keeps is a heap allocation with a matching
//  teardown call (Darwin's `compression_stream_destroy`), and `deinit` is what guarantees the teardown
//  runs when a client disconnects mid-body and the producer is cancelled rather than finished.
//

/// One incremental content-coding encode (RFC 9110 §8.4.1) — stateful, single-use, not thread-safe.
///
/// The contract is the obvious one: ``update(_:)`` for each input chunk in order, then ``finish()``
/// exactly once. The concatenation of everything returned must be byte-identical to what the matching
/// ``ContentEncoder/encode(_:)`` produces for the concatenated input, so the buffered and streamed
/// paths of a response are the same representation and a `Vary: Accept-Encoding` cache cannot end up
/// holding two different bodies for one resource.
///
/// Not `Sendable`: an instance belongs to exactly one response body and is serialized by the writer
/// that owns it (``CompressingBodyWriter``), which is where the isolation is stated.
public protocol ContentEncoderStream: AnyObject {
    /// Codes `input` and returns whatever output is ready, which is legitimately empty for a backend
    /// still filling its window.
    func update(_ input: [UInt8]) throws(ContentEncodingError) -> [UInt8]

    /// Flushes the backend and returns the trailing octets (a trailer, a final block, or both).
    ///
    /// The stream is spent afterwards: a later ``update(_:)`` throws
    /// ``ContentEncodingError/streamFinished`` rather than silently emitting a second coded stream.
    func finish() throws(ContentEncodingError) -> [UInt8]
}
