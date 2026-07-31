//
//  HandlerExecutionParityTests.swift
//  HTTPServerTests
//
//  The correctness invariant of ``HandlerExecutionPolicy`` (audit CR-F7): the policy decides *where*
//  a handler runs and nothing else. Every policy must serve a byte-identical response on every
//  protocol and both body modes.
//
//  This is the suite that makes the whole change defensible. Lifting the handler off the reactor
//  moves an `await` boundary in six places across three protocol engines; the one thing that must not
//  be observable from the wire is that it happened. So the same request is driven over HTTP/1.1
//  buffered, HTTP/1.1 streaming (RFC 9112 §7), HTTP/2 (RFC 9113) and HTTP/3 (RFC 9114) under every
//  policy, and the status and body are compared against the same expectation.
//

import HTTPCore
import HTTPTransport
import Testing

@testable import HTTPServer

@Suite("Handler execution — every policy serves an identical response (CR-F7)")
struct HandlerExecutionParityTests {
    /// Every policy under test.
    static let policies: [HandlerExecutionPolicy] = [.inline, .concurrent]

    private static let bodySize = 24
    private static let expected = "tag=abc bytes=\(bodySize)"

    /// A `/upload/:tag` router echoing the captured tag and the body size it received.
    private static func router(streaming: Bool) -> Router {
        Router {
            let route = Route.post("/upload/:tag") { _, body, context in
                .text("tag=\(context.parameters["tag"] ?? "?") bytes=\(await body.collect().count)")
            }
            if streaming {
                route.streamingBody()
            }
            else {
                route
            }
        }
    }

    private static func server(
        _ policy: HandlerExecutionPolicy,
        streaming: Bool,
        transport: any ServerTransport
    ) -> HTTPServer<ContinuousClock> {
        HTTPServer(
            transport: transport,
            responder: router(streaming: streaming),
            handlerExecution: policy
        )
    }

    @Test(
        "HTTP/1.1 serves the same response under every policy",
        arguments: policies, [false, true]
    )
    func http1IsIdentical(policy: HandlerExecutionPolicy, streaming: Bool) async {
        let body = String(repeating: "x", count: Self.bodySize)
        let request = """
            POST /upload/abc HTTP/1.1\r
            Host: x\r
            Content-Length: \(Self.bodySize)\r
            Connection: close\r
            \r
            \(body)
            """
        let connection = FakeConnection(id: TransportConnectionID(1), inbound: Array(request.utf8))
        let server = Self.server(policy, streaming: streaming, transport: FakeTransport())
        await server.serve(connection)

        let wire = String(decoding: await connection.sentBytes(), as: Unicode.UTF8.self)
        #expect(wire.hasPrefix("HTTP/1.1 200 OK\r\n"))
        #expect(wire.hasSuffix(Self.expected))
    }

    @Test("HTTP/2 serves the same response under every policy", arguments: policies, [false, true])
    func http2IsIdentical(policy: HandlerExecutionPolicy, streaming: Bool) async throws {
        let connection = FakeConnection(
            id: TransportConnectionID(1),
            inbound: DispatchPlanWire.http2Head(path: "/upload/abc")
                + DispatchPlanWire.http2Body(count: Self.bodySize)
        )
        let server = Self.server(policy, streaming: streaming, transport: FakeTransport())
        await server.serve(connection)

        let response = try DispatchPlanWire.decodeHTTP2(await connection.sentBytes())
        #expect(response.status == "200")
        #expect(String(decoding: response.body, as: Unicode.UTF8.self) == Self.expected)
    }

    @Test("HTTP/3 serves the same response under every policy", arguments: policies, [false, true])
    func http3IsIdentical(policy: HandlerExecutionPolicy, streaming: Bool) async throws {
        let server = try Self.server(
            policy,
            streaming: streaming,
            transport: TransportFactory.make(TransportConfiguration(port: 0, backbone: .fake))
        )
        let quic = FakeQUICConnection()
        let stream = FakeQUICStream(
            id: QUICStreamID(0),
            direction: .bidirectional,
            inbound: [
                (
                    DispatchPlanWire.http3Head(path: "/upload/abc", contentLength: Self.bodySize)
                        + DispatchPlanWire.http3Body(count: Self.bodySize), true
                )
            ]
        )
        let serving = Task { await server.serveHTTP3(quic) }
        defer { serving.cancel() }
        quic.accept(stream)
        try await DispatchPlanWire.settle { stream.sendCount > 0 }

        let (status, body) = try DispatchPlanWire.decodeHTTP3(stream.sentBytes)
        #expect(status == "200")
        #expect(String(decoding: body, as: Unicode.UTF8.self) == Self.expected)
    }
}
