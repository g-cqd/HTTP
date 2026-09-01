//
//  BodyLimitMiddlewareTests.swift
//  HTTPServerTests
//
//  ``BodyLimitMiddleware`` as a *streaming* limit (RFC 9110 §15.5.14). It used to enforce its cap by
//  collecting the whole body and measuring afterwards, which both defeated streaming for every route
//  it guarded and buffered the very body it was meant to refuse. It must now count while forwarding:
//  chunks reach the responder one at a time, and an over-limit body trips the moment the crossing
//  chunk arrives, leaving the rest of the producer unread (CWE-400).
//

import HTTPCore
import Testing

@testable import HTTPServer

@Suite("Middleware — streaming body limit (RFC 9110 §15.5.14, CWE-400)")
struct BodyLimitMiddlewareTests {
    private static let request = HTTPRequest(
        method: .post, scheme: "https", authority: "x", path: "/"
    )

    /// A responder that drains the body and reports the octet count it saw.
    private let counting = ClosureResponder { _, body, _ in
        ServerResponse(HTTPResponse(status: .ok), body: Array("\(await body.collect().count)".utf8))
    }

    @Test("an over-limit streamed body is refused WITHOUT reading the rest of it")
    func overLimitStreamStopsEarly() async {
        // 64 chunks of 16 octets against a 64-octet cap: the fifth chunk crosses it, so at most five
        // are ever pulled. A collect-then-measure limit reads all sixty-four first.
        let producer = PullBodyProducer(chunkCount: 64, size: 16)
        let middleware = BodyLimitMiddleware(maxBytes: 64)
        let response = await middleware.respond(
            to: Self.request,
            body: producer.makeBody(),
            context: RequestContext(),
            next: counting
        )
        #expect(response.head.status == .contentTooLarge)
        #expect(await producer.isDrained == false)
        #expect(await producer.pulled <= 5)
    }

    @Test("a streamed body within the limit reaches the responder whole")
    func withinLimitStreamPassesThrough() async {
        let producer = PullBodyProducer(chunkCount: 4, size: 16)
        let middleware = BodyLimitMiddleware(maxBytes: 64)
        let response = await middleware.respond(
            to: Self.request,
            body: producer.makeBody(),
            context: RequestContext(),
            next: counting
        )
        #expect(response.head.status == .ok)
        #expect(String(decoding: response.body, as: Unicode.UTF8.self) == "64")
        #expect(await producer.isDrained)
    }

    @Test("the body still reaches the responder chunk by chunk, not coalesced")
    func forwardsChunkWise() async {
        let producer = PullBodyProducer(chunkCount: 6, size: 8)
        let observed = ChunkRecorder()
        let responder = ClosureResponder { _, body, _ in
            for await chunk in body.asStream {
                await observed.record(chunk.count)
            }
            return ServerResponse(HTTPResponse(status: .ok))
        }
        let middleware = BodyLimitMiddleware(maxBytes: 1_024)
        _ = await middleware.respond(
            to: Self.request,
            body: producer.makeBody(),
            context: RequestContext(),
            next: responder
        )
        #expect(await observed.sizes == [8, 8, 8, 8, 8, 8])
    }

    @Test("an already-buffered over-limit body is still refused")
    func bufferedOverLimitRefused() async {
        let middleware = BodyLimitMiddleware(maxBytes: 4)
        let response = await middleware.respond(
            to: Self.request,
            body: .collected(Array("hello".utf8)),
            context: RequestContext(),
            next: counting
        )
        #expect(response.head.status == .contentTooLarge)
    }

    @Test("an already-buffered body within the limit passes through")
    func bufferedWithinLimitPasses() async {
        let middleware = BodyLimitMiddleware(maxBytes: 8)
        let response = await middleware.respond(
            to: Self.request,
            body: .collected(Array("hello".utf8)),
            context: RequestContext(),
            next: counting
        )
        #expect(response.head.status == .ok)
        #expect(String(decoding: response.body, as: Unicode.UTF8.self) == "5")
    }
}
