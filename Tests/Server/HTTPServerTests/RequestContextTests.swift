//
//  RequestContextTests.swift
//  HTTPServerTests
//
//  The request seam (Phase 1.0/1.1): the explicit ``RequestContext`` (connection metadata, correlation
//  id, route parameters, typed storage bag) and ``RequestBody`` (buffered or streamed) threaded through
//  the responder. Covers the storage bag's type-safety + value semantics, the body accessors, and the
//  engine populating the context from the connection on the real HTTP/1.1 serve path (over a
//  `FakeConnection`, no sockets).
//

import HTTPCore
import HTTPTestSupport
import HTTPTransport
import Testing

@testable import HTTPServer

@Suite("Request seam — RequestContext + RequestBody")
struct RequestContextTests {
    private enum UserKey: RequestStorageKey { typealias Value = String }
    private enum AttemptKey: RequestStorageKey { typealias Value = Int }

    // MARK: Typed storage bag

    @Test("storage returns nil for an unset key")
    func storageNilByDefault() {
        let context = RequestContext()
        #expect(context[UserKey.self] == nil)
        #expect(context[AttemptKey.self] == nil)
    }

    @Test("storage round-trips typed values keyed by their RequestStorageKey")
    func storageRoundTrips() {
        var context = RequestContext()
        context[UserKey.self] = "alice"
        context[AttemptKey.self] = 3
        #expect(context[UserKey.self] == "alice")
        #expect(context[AttemptKey.self] == 3)
    }

    @Test("writing nil removes a stored value")
    func storageRemovesOnNil() {
        var context = RequestContext()
        context[UserKey.self] = "alice"
        context[UserKey.self] = nil
        #expect(context[UserKey.self] == nil)
    }

    @Test("storage has value semantics — a copy's write never disturbs the original (COW)")
    func storageValueSemantics() {
        var original = RequestContext()
        original[UserKey.self] = "alice"
        var copy = original
        copy[UserKey.self] = "bob"
        #expect(original[UserKey.self] == "alice")
        #expect(copy[UserKey.self] == "bob")
    }

    // MARK: RequestBody accessors

    @Test("a collected body exposes its bytes synchronously and via collect()")
    func collectedBody() async {
        let body = RequestBody.collected(Array("hi".utf8))
        #expect(body.isStreaming == false)
        #expect(body.bytes == Array("hi".utf8))
        #expect(await body.collect() == Array("hi".utf8))
    }

    @Test("a streamed body has no synchronous bytes and drains via collect()")
    func streamedBody() async {
        let stream = HTTPRequestBodyStream(
            AsyncStream { continuation in
                continuation.yield(Array("he".utf8))
                continuation.yield(Array("llo".utf8))
                continuation.finish()
            }
        )
        let body = RequestBody.stream(stream)
        #expect(body.isStreaming)
        #expect(body.bytes == nil)
        #expect(await body.collect() == Array("hello".utf8))
    }

    @Test("asStream over a collected body yields the buffered bytes once")
    func collectedAsStream() async {
        var chunks: [[UInt8]] = []
        for await chunk in RequestBody.collected(Array("data".utf8)).asStream {
            chunks.append(chunk)
        }
        #expect(chunks == [Array("data".utf8)])
    }

    // MARK: Connection metadata reaches the handler (HTTP/1.1 serve path)

    @Test("the engine populates context.connection from the transport connection (HTTP/1.1)")
    func connectionContextOverH1() async {
        let connection = FakeConnection(
            id: TransportConnectionID(7),
            peer: TransportAddress(host: "10.0.0.9", port: 5_555),
            negotiatedApplicationProtocol: "http/1.1",
            isSecure: true,
            inbound: Array("GET / HTTP/1.1\r\nHost: x\r\n\r\n".utf8)
        )
        let responder = ClosureResponder { _, _, context in
            let connection = context.connection
            let identified = connection.id == TransportConnectionID(7) ? "id7" : "id?"
            let host = connection.peer?.host ?? "-"
            let alpn = connection.negotiatedApplicationProtocol ?? "-"
            return .text("\(host)|\(connection.isSecure)|\(alpn)|\(identified)")
        }
        let wire = await serve(connection, with: responder)
        #expect(wire.hasSuffix("\r\n\r\n10.0.0.9|true|http/1.1|id7"))
    }

    // MARK: Correlation id

    @Test("a valid inbound X-Request-ID propagates to context.id (no middleware)")
    func inboundRequestIDPropagates() async {
        let connection = FakeConnection(
            id: TransportConnectionID(1),
            inbound: Array("GET / HTTP/1.1\r\nHost: x\r\nX-Request-ID: corr-9\r\n\r\n".utf8)
        )
        let responder = ClosureResponder { _, _, context in .text(context.id ?? "<none>") }
        let wire = await serve(connection, with: responder)
        #expect(wire.hasSuffix("\r\n\r\ncorr-9"))
    }

    @Test("RequestIDMiddleware surfaces the resolved id on context.id (minted when absent)")
    func requestIDMiddlewareSetsContextID() async {
        let handler = ClosureResponder { _, _, context in .text(context.id ?? "<none>") }
        let responder = handler.wrapped(by: RequestIDMiddleware { "minted-id" })
        let request = HTTPRequest(method: .get, scheme: "https", authority: "x", path: "/")
        let response = await responder.respond(to: request, body: [])
        #expect(response.body == Array("minted-id".utf8))
    }

    // MARK: Middleware → handler storage handoff

    @Test("middleware stores typed data the handler reads back, through the chain")
    func middlewarePassesStorageToHandler() async {
        let handler = ClosureResponder { _, _, context in
            .text(context[UserKey.self] ?? "<anon>")
        }
        let chain = MiddlewareChain(
            [AuthenticatingMiddleware(user: "alice")], terminatingAt: handler
        )
        let response = await chain.respond(
            to: HTTPRequest(method: .get, scheme: "https", authority: "x", path: "/"),
            body: []
        )
        #expect(response.body == Array("alice".utf8))
    }

    // MARK: Helpers

    /// A middleware that authenticates a request by writing the user into the context storage bag.
    private struct AuthenticatingMiddleware: HTTPMiddleware {
        let user: String

        func respond(
            to request: HTTPRequest,
            body: RequestBody,
            context: RequestContext,
            next: any HTTPResponder
        ) async -> ServerResponse {
            var context = context
            context[UserKey.self] = user
            return await next.respond(to: request, body: body, context: context)
        }
    }

    /// Serves one request through the real HTTP/1.1 pipeline over `connection`, returning the wire bytes.
    private func serve(
        _ connection: FakeConnection,
        with responder: any HTTPResponder
    ) async -> String {
        let server = HTTPServer(transport: FakeTransport(), responder: responder)
        await server.serve(connection)
        return String(decoding: await connection.sentBytes(), as: Unicode.UTF8.self)
    }
}
