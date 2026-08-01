//
//  WebSocketUpgradeIngressTests.swift
//  HTTPServerTests
//
//  Audit R5-SEC1 — the WebSocket upgrade path used to bypass the CR-F13 ingress strip.
//
//  CR-F13 established one choke point that removes every client-supplied ``HTTPFieldName/serverAsserted``
//  field before any responder sees a request, because a handler reading one of them is reading a server
//  assertion (RFC 9110 §17.1; CWE-290, spoofing; CWE-807, untrusted input in a security decision). The
//  HTTP/2 and HTTP/3 Extended CONNECT paths (RFC 8441 / RFC 9220) never went through it: they take the
//  request straight off the engine event and hand it to ``WebSocketHandler/shouldUpgrade(_:)``, which is
//  precisely where an application decides whether a peer may open a socket. A client could therefore
//  spoof `X-Auth-Subject` on the one route that skipped the strip and have the handler authorize it.
//
//  ``ServerAssertedIngressTests`` covers ordinary requests on all three protocols; this covers the
//  upgrade path, which is a different seam — `shouldUpgrade` is the only place a WebSocket handler is
//  ever shown request fields at all, since every later hook is given frames.
//
//  The fix is structural rather than a call-site discipline: `shouldUpgrade` now takes a
//  ``SanitizedRequest``, a type whose only initializer performs the strip, so an unstripped request
//  cannot reach the seam even from a call site nobody has audited. These tests drive the real h2 and h3
//  engines end to end, parameterized over the whole `serverAsserted` list so a field added to it
//  without an upgrade-path strip fails here.
//

import HPACK
import HTTPCore
import HTTPTestSupport
import HTTPTransport
import QPACK
import Testing
import WebSocket

@testable import HTTPServer

@Suite("WebSocket upgrade — the ingress strip covers Extended CONNECT (R5-SEC1)")
struct WebSocketUpgradeIngressTests {
    /// The value a hostile client puts on the server-asserted field it is spoofing.
    private static let spoof = "attacker"

    // MARK: HTTP/2 (RFC 8441)

    @Test(
        "HTTP/2: a spoofed server-asserted field never reaches the upgrade handler",
        arguments: HTTPFieldName.serverAsserted
    )
    func http2UpgradeStripsInboundAssertion(_ name: HTTPFieldName) async {
        let seen = SeenField()
        let handler = RecordingUpgradeHandler(field: name, seen: seen)
        let connection = FakeConnection(
            id: TransportConnectionID(1),
            inbound: H2ServerWire.preface + H2ServerWire.settings()
                + H2ServerWire.headers(
                    streamID: 1,
                    method: "CONNECT",
                    path: "/chat",
                    extra: [
                        HPACKField(name: ":protocol", value: "websocket"),
                        HPACKField(name: name.canonicalName, value: Self.spoof)
                    ]
                )
        )
        let server = HTTPServer(
            transport: FakeTransport(),
            responder: Router { Route.webSocket("/chat", handler: handler) }
        )
        await server.serve(connection)
        #expect(seen.wasAsked)  // the upgrade really was authorized through this seam
        #expect(seen.recorded == nil)
    }

    // MARK: HTTP/3 (RFC 9220)

    @Test(
        "HTTP/3: a spoofed server-asserted field never reaches the upgrade handler",
        arguments: HTTPFieldName.serverAsserted
    )
    func http3UpgradeStripsInboundAssertion(_ name: HTTPFieldName) async throws {
        let seen = SeenField()
        let handler = RecordingUpgradeHandler(field: name, seen: seen)
        let server = HTTPServer(
            transport: try TransportFactory.make(TransportConfiguration(port: 0, backbone: .fake)),
            responder: Router { Route.webSocket("/chat", handler: handler) }
        )
        let quic = FakeQUICConnection()
        let stream = FakeQUICStream(
            id: QUICStreamID(0),
            direction: .bidirectional,
            inbound: [(Self.h3ExtendedConnect(spoofing: name), false)]
        )
        let serving = Task { await server.serveHTTP3(quic) }
        defer { serving.cancel() }
        quic.accept(stream)
        try await Self.settle { seen.wasAsked }
        #expect(seen.wasAsked)
        #expect(seen.recorded == nil)
    }

    // MARK: The strip is not reachable around — construction is the only way in

    @Test(
        "a SanitizedRequest never carries a server-asserted field, whatever it was built from",
        arguments: HTTPFieldName.serverAsserted
    )
    func sanitizingIsTheOnlyConstructor(_ name: HTTPFieldName) {
        var fields = HTTPFields()
        _ = fields.append(Self.spoof, for: name)
        let raw = HTTPRequest(
            method: .get, scheme: "https", authority: "x", path: "/", headerFields: fields
        )
        #expect(raw.headerFields[name] == Self.spoof)
        #expect(SanitizedRequest(raw).request.headerFields[name] == nil)
    }

    @Test("sanitizing leaves every other field, and the request line, untouched")
    func sanitizingIsSurgical() {
        var fields = HTTPFields()
        _ = fields.append("bearer abc", for: .authorization)
        _ = fields.append(Self.spoof, for: .xAuthSubject)
        _ = fields.append("websocket", for: .upgrade)
        let sanitized = SanitizedRequest(
            HTTPRequest(
                method: .get, scheme: "https", authority: "x", path: "/chat", headerFields: fields
            )
        )
        #expect(sanitized.request.headerFields[.authorization] == "bearer abc")
        #expect(sanitized.request.headerFields[.upgrade] == "websocket")
        #expect(sanitized.request.headerFields[.xAuthSubject] == nil)
        #expect(sanitized.request.path == "/chat")
        #expect(sanitized.request.method == .get)
    }

    // MARK: - Wire helpers

    /// An h3 HEADERS frame (RFC 9114 §7.2.2) carrying an Extended CONNECT that spoofs `name`.
    private static func h3ExtendedConnect(spoofing name: HTTPFieldName) -> [UInt8] {
        let section = QPACKEncoder()
            .encode([
                HeaderField(name: ":method", value: "CONNECT"),
                HeaderField(name: ":protocol", value: "websocket"),
                HeaderField(name: ":scheme", value: "https"),
                HeaderField(name: ":authority", value: "example.com"),
                HeaderField(name: ":path", value: "/chat"),
                HeaderField(name: name.canonicalName, value: spoof)
            ])
        var out: [UInt8] = []
        QUICVarint.encode(0x01, into: &out)
        QUICVarint.encode(UInt64(section.count), into: &out)
        out.append(contentsOf: section)
        return out
    }

    /// Polls `condition` on the cooperative pool until it holds or the budget runs out.
    private static func settle(until condition: @Sendable () -> Bool) async throws {
        for _ in 0 ..< 200 where !condition() {
            try await Task.sleep(for: .milliseconds(10))
        }
    }
}
