//
//  HTTPServer+Streaming.swift
//  HTTPServer
//
//  Response-body streaming. HTTP/1.1 streams natively (``sendStreamedResponse(_:stream:omitBody:on:)``):
//  the head goes out with chunked transfer-coding (RFC 9112 §7.1), or a fixed Content-Length when the
//  producer declared one, then each chunk is written as it is produced. Engines without native streaming
//  yet (HTTP/2, HTTP/3) collapse a *finite* stream to one buffer (``bufferedResponse(_:)``) and fail with
//  500 rather than buffer an unbounded one — so Server-Sent Events is HTTP/1.1-only until those engines
//  stream natively. Streaming assumes HTTP/1.1 framing (chunked is not valid for an HTTP/1.0 peer).
//

internal import HTTP1
internal import HTTPCore
internal import HTTPTransport

#if canImport(Darwin)
    internal import Darwin
#elseif canImport(Glibc)
    internal import Glibc
#endif

extension HTTPServer {
    /// Streams a response over HTTP/1.1.
    ///
    /// The head goes out chunked (or with Content-Length when the producer declared one), then each body
    /// chunk as it is produced; a chunked stream is terminated. Returns false on a transport fault.
    func sendStreamedResponse(
        _ head: HTTPResponse,
        stream: ResponseStream,
        omitBody: Bool,
        on connection: any TransportConnection
    ) async -> Bool {
        var head = head
        let chunked = stream.contentLength == nil
        if let length = stream.contentLength {
            _ = head.headerFields.setValue(String(length), for: .contentLength)
        }
        else {
            _ = head.headerFields.setValue("chunked", for: .transferEncoding)
        }
        do {
            try await connection.send(ResponseSerializer.serialize(head, body: [], omitBody: false))
            guard !omitBody else {
                return true  // HEAD: the header section only (RFC 9112 §6.3)
            }
            try await stream.produce(H1StreamWriter(connection: connection, chunked: chunked))
            if chunked {
                try await connection.send(Array("0\r\n\r\n".utf8))  // last-chunk (RFC 9112 §7.1)
            }
            return true
        }
        catch {
            return false
        }
    }

    /// Collapses a streamed response to a buffered one for engines without native streaming yet (h2/h3).
    ///
    /// Runs the producer into a capped buffer, or returns a `500` if it would exceed the cap, so an
    /// unbounded stream fails rather than being silently truncated. A non-streamed response is returned
    /// unchanged.
    func bufferedResponse(_ response: ServerResponse) async -> ServerResponse {
        guard let stream = response.stream else {
            return response
        }
        guard let body = await stream.collect(maxBytes: limits.maxBodySize) else {
            return ServerResponse(HTTPResponse(status: .internalServerError))
        }
        return ServerResponse(response.head, body: body)
    }

    /// Writes HTTP/1.1 body chunks: chunked transfer-coding (RFC 9112 §7.1), or raw when length is known.
    private struct H1StreamWriter: ResponseBodyWriter {
        let connection: any TransportConnection
        let chunked: Bool

        func write(_ chunk: [UInt8]) async throws {
            guard !chunk.isEmpty else {
                return
            }
            guard chunked else {
                try await connection.send(chunk)
                return
            }
            var frame = Array("\(String(chunk.count, radix: 16))\r\n".utf8)
            frame.append(contentsOf: chunk)
            frame.append(contentsOf: [0x0D, 0x0A])
            try await connection.send(frame)
        }

        /// Hands an unframed file region to the transport's `sendfile(2)` path (G5).
        ///
        /// Only the raw (known `Content-Length`) body qualifies: its octets go on the wire unframed,
        /// so the kernel can copy file pages straight to the socket. A chunked body interleaves
        /// size-line framing per chunk (RFC 9112 §7.1), so it keeps the copying chunk pump — as do
        /// the backbones without a raw socket (the ``TransportConnection`` default).
        func writeFile(atPath path: String, offset: Int, length: Int) async throws {
            guard !chunked, length > 0 else {
                try await FileRegionStreamer.stream(
                    atPath: path, offset: offset, length: length, to: self
                )
                return
            }
            let file = open(path, O_RDONLY)
            guard file >= 0 else {
                throw FileRegionStreamer.FileError.unreadable
            }
            defer { close(file) }
            try await connection.sendFile(descriptor: file, offset: offset, length: length)
        }
    }
}
