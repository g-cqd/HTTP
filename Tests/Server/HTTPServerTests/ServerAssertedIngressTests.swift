//
//  ServerAssertedIngressTests.swift
//  HTTPServerTests
//
//  Audit CR-F13 — the ingress strip. A handful of request fields are *server*-asserted: the server (or
//  a middleware above the handler) is their only legitimate source, and a handler that reads one is
//  entitled to treat it as a server assertion. A client that supplies one on the wire is therefore
//  spoofing an authorization decision (CWE-290, identity spoofing; CWE-807, reliance on an untrusted
//  input), and RFC 9110 §17.1 puts the burden on the recipient: a field's meaning is whatever the
//  recipient's own processing makes of it, so it must not accept an assertion it did not make.
//
//  The strip belongs at the ingress choke point, not in each asserting middleware: a middleware only
//  overwrites the field when it has something to assert, so any conditional assertion (a verified JWT
//  with no `sub`, a `ForwardAuthMiddleware` decision that omits a name) silently forwards the client's
//  value instead. These tests drive the real serve pipeline for all three protocols, parameterized over
//  ``HTTPFieldName/serverAsserted`` so a field added to that list without an ingress strip fails here.
//

import HPACK
import HTTP2
import HTTPCore
import HTTPTestSupport
import HTTPTransport
import QPACK
import Testing

@testable import HTTPServer

@Suite("Ingress strip — a client cannot supply a server-asserted field (CR-F13)")
struct ServerAssertedIngressTests {
    /// The value a hostile client puts on every server-asserted field.
    private static let spoof = "attacker"

    /// A responder echoing back what the handler sees on `name` — `<none>` when it was stripped.
    private static func echo(_ name: HTTPFieldName) -> any HTTPResponder {
        ClosureResponder { request, _, _ in
            ServerResponse(
                HTTPResponse(status: .ok),
                body: Array((request.headerFields[name] ?? "<none>").utf8)
            )
        }
    }

    // MARK: HTTP/1.1

    @Test(
        "HTTP/1.1: a client-supplied server-asserted field never reaches the handler",
        arguments: HTTPFieldName.serverAsserted
    )
    func http1StripsInboundAssertion(_ name: HTTPFieldName) async {
        let request = """
            GET / HTTP/1.1\r
            Host: x\r
            \(name.canonicalName): \(Self.spoof)\r
            \r

            """
        let connection = FakeConnection(id: TransportConnectionID(1), inbound: Array(request.utf8))
        let server = HTTPServer(transport: FakeTransport(), responder: Self.echo(name))
        await server.serve(connection)
        let wire = String(decoding: await connection.sentBytes(), as: Unicode.UTF8.self)
        #expect(wire.hasSuffix("\r\n\r\n<none>"))
        #expect(!wire.contains(Self.spoof))
    }

    // MARK: HTTP/2

    @Test(
        "HTTP/2: a client-supplied server-asserted field never reaches the handler",
        arguments: HTTPFieldName.serverAsserted
    )
    func http2StripsInboundAssertion(_ name: HTTPFieldName) async throws {
        let connection = FakeConnection(
            id: TransportConnectionID(1),
            inbound: H2ServerWire.preface + H2ServerWire.settings()
                + H2ServerWire.headers(
                    streamID: 1,
                    method: "GET",
                    path: "/",
                    endStream: true,
                    extra: [HPACKField(name: name.canonicalName, value: Self.spoof)]
                )
        )
        let server = HTTPServer(transport: FakeTransport(), responder: Self.echo(name))
        await server.serve(connection)
        let response = try Self.decodeHTTP2(await connection.sentBytes())
        #expect(response.status == "200")
        #expect(String(decoding: response.body, as: Unicode.UTF8.self) == "<none>")
    }

    // MARK: HTTP/3

    @Test(
        "HTTP/3: a client-supplied server-asserted field never reaches the handler",
        arguments: HTTPFieldName.serverAsserted
    )
    func http3StripsInboundAssertion(_ name: HTTPFieldName) async throws {
        let server = HTTPServer(
            transport: try TransportFactory.make(TransportConfiguration(port: 0, backbone: .fake)),
            responder: Self.echo(name)
        )
        let quic = FakeQUICConnection()
        let stream = FakeQUICStream(
            id: QUICStreamID(0),
            direction: .bidirectional,
            inbound: [(Self.h3Headers(spoofing: name), true)]
        )
        let serving = Task { await server.serveHTTP3(quic) }
        defer { serving.cancel() }
        quic.accept(stream)
        try await Self.settle { stream.sendCount > 0 }
        let (status, body) = try Self.decodeHTTP3(stream.sentBytes)
        #expect(status == "200")
        #expect(String(decoding: body, as: Unicode.UTF8.self) == "<none>")
    }

    // MARK: The request id survives as a context value, not as a header

    @Test("a valid inbound X-Request-ID reaches context.id but not the handler's headers")
    func requestIDBecomesContextValue() async {
        let responder = ClosureResponder { request, _, context in
            let seen = request.headerFields[.xRequestID] ?? "<none>"
            return ServerResponse(
                HTTPResponse(status: .ok), body: Array("\(context.id ?? "<nil>")|\(seen)".utf8)
            )
        }
        let request = "GET / HTTP/1.1\r\nHost: x\r\nX-Request-ID: abc123\r\n\r\n"
        let connection = FakeConnection(id: TransportConnectionID(1), inbound: Array(request.utf8))
        let server = HTTPServer(transport: FakeTransport(), responder: responder)
        await server.serve(connection)
        let wire = String(decoding: await connection.sentBytes(), as: Unicode.UTF8.self)
        #expect(wire.hasSuffix("\r\n\r\nabc123|<none>"))
    }

    @Test("RequestIDMiddleware still correlates a front proxy's inbound id through the context")
    func requestIDMiddlewareCorrelatesThroughContext() async {
        let responder = ClosureResponder { request, _, _ in
            .text(request.headerFields[.xRequestID] ?? "<none>")
        }
        let request = "GET / HTTP/1.1\r\nHost: x\r\nX-Request-ID: proxy-42\r\n\r\n"
        let connection = FakeConnection(id: TransportConnectionID(1), inbound: Array(request.utf8))
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: MiddlewareChain([RequestIDMiddleware()], terminatingAt: responder)
        )
        await server.serve(connection)
        let wire = String(decoding: await connection.sentBytes(), as: Unicode.UTF8.self)
        #expect(wire.hasSuffix("\r\n\r\nproxy-42"))
    }

    // MARK: - Wire helpers

    private static func decodeHTTP2(_ bytes: [UInt8]) throws -> (status: String?, body: [UInt8]) {
        var decoder = HPACKDecoder(maxDynamicTableSize: 4_096)
        var status: String?
        var body: [UInt8] = []
        try bytes.withUnsafeBytes { raw in
            var reader = ByteReader(raw)
            let frames = HTTP2FrameDecoder()
            while let frame = try frames.nextFrame(&reader) {
                switch frame.header.type {
                    case .headers:
                        let fragment = try HTTP2HeadersFrame.fieldBlockFragment(
                            frame.payload, flags: frame.header.flags
                        )
                        let fields = try Array(fragment)
                            .withUnsafeBytes { try decoder.decode($0.bytes) }
                        for field in fields where field.name == ":status" { status = field.value }
                    case .data:
                        body.append(contentsOf: frame.payload)
                    default:
                        break
                }
            }
        }
        return (status, body)
    }

    /// A HEADERS frame (RFC 9114 §7.2.2) whose field section spoofs `name`.
    private static func h3Headers(spoofing name: HTTPFieldName) -> [UInt8] {
        let section = QPACKEncoder()
            .encode([
                HeaderField(name: ":method", value: "GET"),
                HeaderField(name: ":scheme", value: "https"),
                HeaderField(name: ":authority", value: "example.com"),
                HeaderField(name: ":path", value: "/"),
                HeaderField(name: name.canonicalName, value: spoof)
            ])
        var out: [UInt8] = []
        QUICVarint.encode(0x01, into: &out)
        QUICVarint.encode(UInt64(section.count), into: &out)
        out.append(contentsOf: section)
        return out
    }

    private static func decodeHTTP3(_ bytes: [UInt8]) throws -> (String?, [UInt8]) {
        var status: String?
        var body: [UInt8] = []
        var index = 0
        while index < bytes.count {
            guard let frame = Self.nextHTTP3Frame(Array(bytes[index...])) else {
                break
            }
            index += frame.consumed
            switch frame.type {
                case 0x01:
                    let fields = try frame.payload.withUnsafeBytes {
                        try QPACKDecoder().decode($0.bytes)
                    }
                    for field in fields where field.name == ":status" { status = field.value }
                case 0x00:
                    body.append(contentsOf: frame.payload)
                default:
                    break
            }
        }
        return (status, body)
    }

    private static func nextHTTP3Frame(
        _ bytes: [UInt8]
    ) -> (type: UInt64, payload: [UInt8], consumed: Int)? {
        bytes.withUnsafeBytes { raw -> (type: UInt64, payload: [UInt8], consumed: Int)? in
            var reader = ByteReader(raw)
            guard let type = QUICVarint.decode(&reader),
                let length = QUICVarint.decode(&reader),
                reader.position + Int(length) <= bytes.count
            else {
                return nil
            }
            let start = reader.position
            return (type, Array(bytes[start ..< (start + Int(length))]), start + Int(length))
        }
    }

    /// Polls `condition` on the cooperative pool until it holds or the budget runs out.
    private static func settle(until condition: @Sendable () -> Bool) async throws {
        for _ in 0 ..< 200 where !condition() {
            try await Task.sleep(for: .milliseconds(10))
        }
    }
}
