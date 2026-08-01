//
//  StreamingCompressionTests.swift
//  HTTPServerTests
//
//  Streamed responses were served uncoded whatever the client offered — SSE, chunked downloads,
//  generated bodies and every static file over the streaming threshold. They are now coded through a
//  ``CompressingBodyWriter``, which is only worth having if it codes *without accumulating*; a
//  compressor that buffered the body to code it would be strictly worse than not coding at all.
//
//  So these pin four things: that the coded octets are byte-identical to the buffered path's (or a
//  `Vary`-keyed cache could hold two bodies for one representation), that each of the three ways to
//  decline actually declines, that nothing accumulates across a large body, and that a body abandoned
//  mid-stream releases the codec at a point the code names rather than whenever ARC gets to it.
//

internal import Compression
internal import HTTPCore
internal import HTTPTransport
import Testing

@testable import HTTPServer

// MARK: - Fixtures

/// Compressible text, comfortably over the default 1 KiB floor.
private let payload = Array(
    String(repeating: "streamed compressible text 0123456789\n", count: 512).utf8
)

/// A `GET` carrying `accept`, or none at all.
private func request(_ accept: String?) -> HTTPRequest {
    var fields = HTTPFields()
    if let accept {
        _ = fields.append(accept, for: .acceptEncoding)
    }
    return HTTPRequest(
        method: .get, scheme: "https", authority: "x", path: "/", headerFields: fields
    )
}

/// A `200 text/plain` head.
private func head() -> HTTPResponse {
    var fields = HTTPFields()
    _ = fields.append("text/plain", for: .contentType)
    return HTTPResponse(status: .ok, headerFields: fields)
}

/// A responder whose body streams `chunks`, wrapped by `middleware`.
private func streaming(
    _ chunks: [[UInt8]],
    length: Int?,
    through middleware: CompressionMiddleware
) -> any HTTPResponder {
    ClosureResponder { _, _, _ in
        var fields = head().headerFields
        if let length {
            _ = fields.setValue(String(length), for: .contentLength)
        }
        let stream = ResponseStream(contentLength: length) { writer in
            for chunk in chunks {
                try await writer.write(chunk)
            }
        }
        return ServerResponse(HTTPResponse(status: .ok, headerFields: fields), stream: stream)
    }
    .wrapped(by: middleware)
}

/// Runs a response's producer to completion and returns what reached the wire.
private func drain(_ response: ServerResponse) async throws -> RecordingBodyWriter {
    let writer = RecordingBodyWriter()
    try await #require(response.stream).produce(writer)
    return writer
}

// MARK: - It codes, and identically

@Test(
    "RFC 9110 §8.4.1 — a streamed body is coded, byte-identically to the buffered path",
    arguments: ["gzip", "br"]
)
func streamedCodingMatchesBufferedCoding(coding: String) async throws {
    let chunks = stride(from: 0, to: payload.count, by: 700)
        .map { Array(payload[$0 ..< min($0 + 700, payload.count)]) }
    let streamed = streaming(chunks, length: payload.count, through: CompressionMiddleware())
    let response = await streamed.respond(to: request(coding), body: [])

    #expect(response.head.headerFields[.contentEncoding] == coding)
    let buffered = await ClosureResponder { _, _, _ in ServerResponse(head(), body: payload) }
        .wrapped(by: CompressionMiddleware())
        .respond(to: request(coding), body: [])
    #expect(try await drain(response).bytes == buffered.body)
}

@Test("RFC 9110 §12.5.5 — a coded stream carries Vary and drops the stale Content-Length")
func codedStreamHeadersAreConsistent() async throws {
    let streamed = streaming([payload], length: payload.count, through: CompressionMiddleware())
    let response = await streamed.respond(to: request("gzip"), body: [])
    #expect(response.head.headerFields[.contentEncoding] == "gzip")
    #expect(response.head.headerFields[.contentLength] == nil)
    #expect(response.head.headerFields.values(for: .vary).contains("Accept-Encoding"))
    // The stream's own length must go too, or the h1 engine frames an identity length over coded
    // octets instead of framing it chunked (RFC 9112 §6.1).
    #expect(try #require(response.stream).contentLength == nil)
}

// MARK: - The three ways to decline, each on its own

@Test("RFC 9110 §12.5.3 — no acceptable coding leaves the stream untouched")
func declinesWhenNoCodingIsAcceptable() async throws {
    let streamed = streaming([payload], length: payload.count, through: CompressionMiddleware())
    let response = await streamed.respond(to: request("identity"), body: [])
    #expect(response.head.headerFields[.contentEncoding] == nil)
    #expect(response.head.headerFields[.contentLength] == String(payload.count))
    #expect(try await drain(response).bytes == payload)
}

@Test("a stream that announces a length below the floor is left untouched")
func declinesBelowTheSizeFloor() async throws {
    let small = Array("tiny".utf8)
    let streamed = streaming([small], length: small.count, through: CompressionMiddleware())
    let response = await streamed.respond(to: request("gzip"), body: [])
    #expect(response.head.headerFields[.contentEncoding] == nil)
    #expect(response.head.headerFields[.contentLength] == String(small.count))
    #expect(try await drain(response).bytes == small)
}

@Test(
    "a backend with no incremental form falls through to identity rather than buffering",
    arguments: [true, false]
)
func declinesWhenTheBackendCannotStream(conformsToStreaming: Bool) async throws {
    let encoder: any ContentEncoder =
        conformsToStreaming
        ? ProbeContentEncoder(token: "x-probe", lifetime: nil)
        : OneShotOnlyEncoder(token: "x-probe")
    let middleware = CompressionMiddleware(encoders: [encoder])
    let response = await streaming([payload], length: payload.count, through: middleware)
        .respond(to: request("x-probe"), body: [])
    #expect(response.head.headerFields[.contentEncoding] == nil)
    #expect(try await drain(response).bytes == payload)
    // Still `Vary`: a coding *was* negotiated, so the buffered representation of this resource does
    // depend on Accept-Encoding, and the two paths must not disagree about the cache key.
    #expect(response.head.headerFields.values(for: .vary).contains("Accept-Encoding"))
    // The one-shot encoder must remain usable for a buffered body — declining is streaming-only.
    let buffered = ClosureResponder { _, _, _ in ServerResponse(head(), body: payload) }
        .wrapped(by: middleware)
    let bufferedResponse = await buffered.respond(to: request("x-probe"), body: [])
    #expect(bufferedResponse.head.headerFields[.contentEncoding] == "x-probe")
}

// MARK: - Retention

@Test(
    "retention stays bounded across a large coded stream",
    arguments: ["gzip", "br"]
)
func largeCodedStreamDoesNotAccumulate(coding: String) async throws {
    // 16 MiB in ~64 KiB chunks — the shape a static file over the streaming threshold produces.
    // Every chunk differs, or the codec would find the whole body in its window and emit almost
    // nothing until the final flush, which would make the "did it stream?" oracle vacuous.
    var seed: UInt64 = 0x2545_F491_4F6C_DD1D
    let chunks: [[UInt8]] = (0 ..< 256)
        .map { index in
            var chunk: [UInt8] = []
            chunk.reserveCapacity(65_536)
            while chunk.count < 65_536 {
                seed = seed &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
                chunk.append(contentsOf: Array("row \(index) \(seed >> 40) filler text\n".utf8))
            }
            return chunk
        }
    let chunkSize = try #require(chunks.first).count
    let total = chunks.reduce(0) { $0 + $1.count }
    let streamed = streaming(chunks, length: total, through: CompressionMiddleware())
    let response = await streamed.respond(to: request(coding), body: [])
    #expect(response.head.headerFields[.contentEncoding] == coding)

    let writer = try await drain(response)
    let coded = writer.bytes
    #expect(coded.count < total / 2, "the coding did not actually shrink a 16 MiB body")
    // The oracle: had the codec held the body to code it, the wire would have seen one enormous
    // chunk. Every chunk stays within a small constant multiple of one input chunk, whatever the
    // body's length — including the final flush, which is the last element.
    let largest = try #require(writer.counts.max())
    #expect(largest <= 4 * chunkSize, "a coded chunk of \(largest) octets means the codec buffered")
    #expect(writer.counts.count > 8, "the body was emitted in too few pieces to have streamed")
}

// MARK: - Cancellation

@Test("a body abandoned mid-stream releases the codec")
func abandonedStreamReleasesTheCodec() async throws {
    let lifetime = ProbeContentEncoder.Lifetime()
    let encoder = ProbeContentEncoder(token: "x-probe", lifetime: lifetime)
    let responder = ClosureResponder { _, _, _ in
        let stream = ResponseStream(contentLength: payload.count) { writer in
            try await writer.write(payload)
            throw CancellationError()
        }
        return ServerResponse(head(), stream: stream)
    }
    .wrapped(by: CompressionMiddleware(encoders: [encoder]))

    let response = await responder.respond(to: request("x-probe"), body: [])
    #expect(response.head.headerFields[.contentEncoding] == "x-probe")
    #expect(lifetime.liveCount == 1, "the codec is created when the response is built")
    await #expect(throws: CancellationError.self) {
        _ = try await drain(response)
    }
    #expect(lifetime.liveCount == 0, "the codec outlived the body it was coding")
}

@Test("a body that completes normally also releases the codec")
func completedStreamReleasesTheCodec() async throws {
    let lifetime = ProbeContentEncoder.Lifetime()
    let encoder = ProbeContentEncoder(token: "x-probe", lifetime: lifetime)
    let response = await streaming(
        [payload],
        length: payload.count,
        through: CompressionMiddleware(encoders: [encoder])
    )
    .respond(to: request("x-probe"), body: [])

    #expect(try await drain(response).bytes == ProbeContentEncoder.coded(payload, from: 0))
    #expect(lifetime.liveCount == 0)
}

// MARK: - On the wire

/// The octets after the header section, and the lowercased header section itself.
private func split(_ wire: [UInt8]) throws -> (headers: String, body: [UInt8]) {
    let separator = Array("\r\n\r\n".utf8)
    let start = try #require(
        (0 ..< max(0, wire.count - 3))
            .first { Array(wire[$0 ..< $0 + 4]) == separator }
    )
    // Up to `start + 2`, so the last field keeps its own CRLF and a `"name: value\r\n"` match is exact.
    return (
        String(decoding: wire[..<(start + 2)], as: Unicode.UTF8.self).lowercased(),
        Array(wire[(start + 4)...])
    )
}

/// Reassembles a chunked transfer-coding body (RFC 9112 §7.1).
private func dechunk(_ body: [UInt8]) throws -> [UInt8] {
    var cursor = 0
    var payload: [UInt8] = []
    while true {
        let lineEnd = try #require(
            (cursor ..< max(cursor, body.count - 1))
                .first { body[$0] == 0x0D && body[$0 + 1] == 0x0A }
        )
        let size = try #require(
            Int(String(decoding: body[cursor ..< lineEnd], as: Unicode.UTF8.self), radix: 16)
        )
        guard size > 0 else {
            return payload
        }
        let start = lineEnd + 2
        payload.append(contentsOf: body[start ..< start + size])
        cursor = start + size + 2
    }
}

/// Inflates a gzip member by stripping its 10-octet header and 8-octet trailer.
private func gunzip(_ member: [UInt8]) -> [UInt8] {
    let deflated = Array(member[10 ..< (member.count - 8)])
    var destination = [UInt8](repeating: 0, count: 1 << 20)
    let written = deflated.withUnsafeBufferPointer { source in
        destination.withUnsafeMutableBufferPointer { destination -> Int in
            guard let source = source.baseAddress, let destination = destination.baseAddress else {
                return 0
            }
            return compression_decode_buffer(
                destination, 1 << 20, source, deflated.count, nil, COMPRESSION_ZLIB
            )
        }
    }
    return Array(destination.prefix(written))
}

@Test("RFC 9112 §7.1 — a coded stream goes out chunked, with no Content-Length beside it")
func codedStreamIsFramedChunkedOnTheWire() async throws {
    let responder = ClosureResponder { _, _, _ in
        let stream = ResponseStream(contentLength: payload.count) { writer in
            try await writer.write(payload)
        }
        return ServerResponse(head(), stream: stream)
    }
    .wrapped(by: CompressionMiddleware())

    let connection = FakeConnection(
        id: TransportConnectionID(1),
        inbound: Array("GET / HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip\r\n\r\n".utf8)
    )
    await HTTPServer(transport: FakeTransport(), responder: responder).serve(connection)
    let (headers, body) = try split(await connection.sentBytes())

    #expect(headers.contains("content-encoding: gzip\r\n"))
    #expect(headers.contains("transfer-encoding: chunked\r\n"))
    // Both together is the RFC 9112 §6.1 smuggling shape, and the h1 engine does not strip one.
    #expect(!headers.contains("content-length:"))
    #expect(headers.contains("vary: accept-encoding\r\n"))
    #expect(gunzip(try dechunk(body)) == payload)
}
