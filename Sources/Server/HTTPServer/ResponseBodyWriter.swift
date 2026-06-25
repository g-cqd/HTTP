//
//  ResponseBodyWriter.swift
//  HTTPServer
//
//  The sink an engine hands a ``ResponseStream`` so a handler can push response-body chunks to the wire
//  incrementally. Each `write` suspends until the transport accepts the chunk, so it is the backpressure
//  point: a slow client naturally slows the producer instead of letting it buffer without bound.
//

/// The sink a ``ResponseStream`` writes body chunks to, supplied by the serving engine.
public protocol ResponseBodyWriter: Sendable {
    /// Writes one body chunk, suspending until the transport accepts it (the backpressure point).
    func write(_ chunk: [UInt8]) async throws
}
