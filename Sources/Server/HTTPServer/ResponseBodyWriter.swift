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

    /// Writes `length` octets of the file at `path`, starting at byte `offset`, as body payload —
    /// the file-region form of ``write(_:)`` (G5 static serving).
    ///
    /// The default streams the region through ``write(_:)`` in bounded chunks (works for every
    /// engine and framing). The HTTP/1.1 raw-body writer overrides it to hand the region to the
    /// transport's `sendfile(2)` when the framing permits — an unframed body span under a known
    /// `Content-Length`; HTTP/2 and HTTP/3 keep the default by design, because their DATA/QUIC
    /// framing (and h3's QUIC encryption) wraps every body byte, so a raw file-to-socket kernel copy
    /// is inapplicable there (RFC 9113 §6.1 / RFC 9114 §7.2.4).
    func writeFile(atPath path: String, offset: Int, length: Int) async throws
}

extension ResponseBodyWriter {
    /// Default ``writeFile(atPath:offset:length:)``: stream the region through ``write(_:)`` in
    /// bounded 64 KiB chunks (see ``FileRegionStreamer``).
    public func writeFile(atPath path: String, offset: Int, length: Int) async throws {
        try await FileRegionStreamer.stream(atPath: path, offset: offset, length: length, to: self)
    }
}
