//
//  DecompressionPolicyTests.swift
//  HTTPServerTests
//
//  What ``DecompressionMiddleware`` does *before* it decodes anything: it reads `Content-Encoding`
//  first and leaves a body it will not decode entirely alone — installing it must not silently
//  convert every streamed request into a buffered one — it refuses a configuration that is not a
//  bound, and it treats the field as the ordered list RFC 9110 §8.4.1 says it is rather than as a
//  single token.
//

import HTTPCore
import Testing

@testable import HTTPServer

@Suite("Middleware — inbound decompression policy (RFC 9110 §8.4.1, CWE-409)")
struct DecompressionPolicyTests {
    private func request(_ encoding: String?) -> HTTPRequest {
        var fields = HTTPFields()
        if let encoding {
            _ = fields.append(encoding, for: .contentEncoding)
        }
        return HTTPRequest(
            method: .post, scheme: "https", authority: "x", path: "/", headerFields: fields
        )
    }

    /// A responder that records the chunk boundaries it observed and reports whether the body it was
    /// handed was still a stream.
    private func recordingResponder(
        _ observed: ChunkRecorder,
        _ streaming: StreamingFlag
    ) -> ClosureResponder {
        ClosureResponder { _, body, _ in
            await streaming.record(body.isStreaming)
            for await chunk in body.asStream {
                await observed.record(chunk.count)
            }
            return ServerResponse(HTTPResponse(status: .ok))
        }
    }

    // MARK: The body is not touched before the header is read

    @Test(
        "a streamed body the middleware will not decode stays streamed, chunk by chunk",
        arguments: [nil, "zstd", "gzip, identity-but-unknown"] as [String?]
    )
    func undecodableBodyStaysStreaming(encoding: String?) async throws {
        // `collect()` used to run *before* the `Content-Encoding` check, so merely installing this
        // middleware buffered every request in the server — a silent, global loss of streaming.
        let producer = PullBodyProducer(chunkCount: 5, size: 8)
        let observed = ChunkRecorder()
        let streaming = StreamingFlag()
        let middleware = try #require(DecompressionMiddleware())
        _ = await middleware.respond(
            to: request(encoding),
            body: producer.makeBody(),
            context: RequestContext(),
            next: recordingResponder(observed, streaming)
        )
        #expect(await streaming.wasStreaming == true)
        #expect(await observed.sizes == [8, 8, 8, 8, 8])
    }

    // MARK: A configuration that is not a bound is refused at init

    @Test(
        "an output cap that is not a bound is refused at initialization",
        arguments: [Int.max, 0, -1, Int.min]
    )
    func invalidOutputCapRefused(maxDecompressedSize: Int) {
        #expect(DecompressionMiddleware(maxDecompressedSize: maxDecompressedSize) == nil)
    }

    @Test("a ratio that is not a bound is refused at initialization", arguments: [Int.max, 0, -1])
    func invalidRatioRefused(maxRatio: Int) {
        #expect(DecompressionMiddleware(maxRatio: maxRatio) == nil)
    }

    @Test("a coding-list depth below one is refused at initialization", arguments: [0, -1])
    func invalidCodingDepthRefused(maxCodings: Int) {
        #expect(DecompressionMiddleware(maxCodings: maxCodings) == nil)
    }

    @Test("the shipped configuration is valid")
    func defaultConfigurationIsValid() {
        #expect(DecompressionMiddleware(maxDecompressedSize: 1 << 20, maxRatio: 10) != nil)
    }

    // MARK: The field is an ordered list, decoded right to left

    @Test("Content-Encoding: gzip, br decodes both layers, outermost first (RFC 9110 §8.4.1)")
    func decodesTwoCodingsRightToLeft() async throws {
        let original = Array(String(repeating: "layered body. ", count: 40).utf8)
        // `gzip, br` means gzip was applied first and Brotli second, so the wire bytes are br(gzip(x))
        // and decoding runs from the right.
        let gzipped = try #require(Gzip.compress(original))
        let coded = try #require(Brotli.compress(gzipped))
        let response = try await Self.respond("gzip, br", coded, ratio: 1_000)
        #expect(response.body == original)
        #expect(response.head.headerFields[.contentEncoding] == nil)
        #expect(response.head.headerFields[.contentLength] == String(original.count))
    }

    @Test("a coding we cannot decode below one we can leaves the remaining list in place")
    func peelsOnlyTheCodingsItUnderstands() async throws {
        let original = Array(String(repeating: "partly coded. ", count: 40).utf8)
        let coded = try #require(Gzip.compress(original))
        // `zstd, gzip`: the outermost gzip comes off, the inner zstd is not ours to undo — so the
        // responder must be told the body is still zstd-coded.
        let response = try await Self.respond("zstd, gzip", coded, ratio: 1_000)
        #expect(response.body == original)
        #expect(response.head.headerFields[.contentEncoding] == "zstd")
    }

    @Test("an outermost coding we cannot decode leaves the body untouched")
    func outermostUnknownCodingPassesThrough() async throws {
        let body = Array("still coded".utf8)
        let response = try await Self.respond("gzip, zstd", body)
        #expect(response.body == body)
        #expect(response.head.headerFields[.contentEncoding] == "gzip, zstd")
    }

    @Test("a coding list deeper than the configured depth is refused (RFC 9110 §15.5.16)")
    func tooManyCodingsRefused() async throws {
        let middleware = try #require(DecompressionMiddleware(maxCodings: 2))
        let response = await middleware.respond(
            to: request("gzip, gzip, gzip"),
            body: Array("anything".utf8),
            next: Self.echo
        )
        #expect(response.head.status == .unsupportedMediaType)
    }

    @Test(
        "a malformed coding list is refused rather than half-understood",
        arguments: ["gzip,,gzip", ",gzip", "gzip,", ",", "gzip, br@@"]
    )
    func malformedCodingListRefused(encoding: String) async throws {
        let middleware = try #require(DecompressionMiddleware())
        let response = await middleware.respond(
            to: request(encoding),
            body: Array("anything".utf8),
            next: Self.echo
        )
        #expect(response.head.status == .unsupportedMediaType)
    }

    @Test("the ratio cap is charged against the wire size across every layer")
    func ratioIsChargedAcrossLayers() async throws {
        let original = [UInt8](repeating: 0x41, count: 200_000)
        let gzipped = try #require(Gzip.compress(original))
        let coded = try #require(Brotli.compress(gzipped))
        // Ratio 10 against a few hundred coded octets: no single layer, and no combination of them,
        // may expand past that budget (CWE-409).
        let response = try await Self.respond("gzip, br", coded, ratio: 10)
        #expect(response.head.status == .contentTooLarge)
    }

    // MARK: Fixtures

    /// A responder echoing the request headers and the body it received.
    private static let echo = ClosureResponder { request, body, _ in
        ServerResponse(
            HTTPResponse(status: .ok, headerFields: request.headerFields),
            body: await body.collect()
        )
    }

    /// Runs the middleware over `body` carrying `encoding`, returning what reached ``echo``.
    private static func respond(
        _ encoding: String,
        _ body: [UInt8],
        ratio: Int = HTTPLimits.default.maxDecompressionRatio,
        maxSize: Int = HTTPLimits.default.maxDecompressedBodySize
    ) async throws -> ServerResponse {
        var fields = HTTPFields()
        _ = fields.append(encoding, for: .contentEncoding)
        let request = HTTPRequest(
            method: .post, scheme: "https", authority: "x", path: "/", headerFields: fields
        )
        let middleware = try #require(
            DecompressionMiddleware(maxDecompressedSize: maxSize, maxRatio: ratio)
        )
        return await middleware.respond(to: request, body: body, next: echo)
    }
}
