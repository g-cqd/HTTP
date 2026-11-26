//
//  HTTPClientLoopbackTests.swift
//  HTTPClientTests
//
//  End to end over real loopback sockets: the in-house ``HTTPServer`` on the platform POSIX backbone
//  (kqueue / epoll) answering ``HTTPClient`` — Content-Length and chunked framing, keep-alive reuse
//  (one client port for sequential requests), concurrent requests bounded per origin, redirects,
//  zstd / gzip content decoding, body bounds, and request deadlines.
//

import HTTPCore
import HTTPDeflate
import HTTPTestSupport
import HTTPTransport
import HTTPZstd
import Synchronization
import Testing

@testable import HTTPClient
@testable import HTTPServer

@Suite("HTTPClient — loopback end to end", .realNetwork)
struct HTTPClientLoopbackTests {
    private final class PeerPorts: Sendable {
        let ports = Mutex<Set<UInt16>>([])

        deinit {
            // Nothing to release beyond ARC.
        }
    }

    private static let payload = Array(String(repeating: "documentation ", count: 4_000).utf8)

    private static func responder(peers: PeerPorts) -> ClosureResponder {
        ClosureResponder { request, _, context in
            if let port = context.connection.peer?.port {
                peers.ports.withLock { _ = $0.insert(port) }
            }
            if request.path == "/slow" {
                try? await Task.sleep(for: .seconds(5))
            }
            return route(request.path)
        }
    }

    private static func route(_ path: String) -> ServerResponse {
        switch path {
            case "/hello":
                return response(body: Array("hello".utf8), field: ("\"v1\"", .etag))
            case "/chunked":
                return ServerResponse(
                    HTTPResponse(status: .ok),
                    stream: ResponseStream { writer in
                        for part in ["alpha-", "beta-", "gamma"] {
                            try await writer.write(Array(part.utf8))
                        }
                    }
                )
            case "/zstd":
                let coded = (try? Zstd.compress(payload)) ?? []
                return response(body: coded, field: ("zstd", .contentEncoding))
            case "/gzip":
                return response(body: DeflateCodec.gzip(payload), field: ("gzip", .contentEncoding))
            case "/redirect":
                return response(status: .found, field: ("/hello", .location))
            case "/loop":
                return response(status: .found, field: ("/loop", .location))
            case "/slow":
                return ServerResponse(HTTPResponse(status: .ok))
            default:
                return ServerResponse(HTTPResponse(status: .notFound))
        }
    }

    private static func response(
        status: HTTPStatus = .ok,
        body: [UInt8] = [],
        field: (value: String, name: HTTPFieldName)
    ) -> ServerResponse {
        var fields = HTTPFields()
        _ = fields.append(field.value, for: field.name)
        return ServerResponse(HTTPResponse(status: status, headerFields: fields), body: body)
    }

    private static func withServer(
        _ body: @Sendable (UInt16, PeerPorts) async throws -> Void
    ) async throws {
        #if canImport(Darwin)
            let backbone = TransportBackbone.posixKqueue
        #else
            let backbone = TransportBackbone.posixEpoll
        #endif
        let peers = PeerPorts()
        let transport = try TransportFactory.make(
            TransportConfiguration(
                host: "127.0.0.1",
                port: 0,
                backbone: backbone,
                eventLoopCount: 1
            )
        )
        let server = HTTPServer(transport: transport, responder: responder(peers: peers))
        let runTask = Task { try? await server.run() }
        var port: UInt16 = 0
        for _ in 0 ..< 400 where port == 0 {
            port = transport.boundPort
            if port == 0 { try await Task.sleep(for: .milliseconds(5)) }
        }
        try #require(port != 0)
        do {
            try await body(port, peers)
        }
        catch {
            await server.shutdown(within: .milliseconds(100))
            runTask.cancel()
            throw error
        }
        await server.shutdown(within: .milliseconds(100))
        runTask.cancel()
    }

    @Test("Content-Length and chunked bodies, keep-alive reuse across sequential requests")
    func framingAndKeepAlive() async throws {
        try await Self.withServer { port, peers in
            let client = HTTPClient()
            for _ in 0 ..< 10 {
                let hello = try await client.get("http://127.0.0.1:\(port)/hello")
                #expect(hello.status == .ok && hello.body == Array("hello".utf8))
                #expect(hello.headerFields[.etag] == "\"v1\"")
            }
            let chunked = try await client.get("http://127.0.0.1:\(port)/chunked")
            #expect(String(validating: chunked.body, as: UTF8.self) == "alpha-beta-gamma")
            #expect(peers.ports.withLock(\.count) == 1)
            await client.shutdown()
        }
    }

    @Test("concurrent requests stay within maxConnectionsPerHost and all succeed")
    func concurrentRequestsAreBounded() async throws {
        try await Self.withServer { port, peers in
            var configuration = HTTPClientConfiguration()
            configuration.maxConnectionsPerHost = 3
            let client = HTTPClient(configuration: configuration)
            try await withThrowingTaskGroup(of: Int.self) { group in
                for _ in 0 ..< 30 {
                    group.addTask {
                        try await client.get("http://127.0.0.1:\(port)/hello").body.count
                    }
                }
                for try await count in group {
                    #expect(count == 5)
                }
            }
            #expect(peers.ports.withLock(\.count) <= 3)
            await client.shutdown()
        }
    }

    @Test("decodes zstd and gzip responses and enforces the decoded body bound")
    func contentDecodingAndBounds() async throws {
        try await Self.withServer { port, _ in
            let client = HTTPClient()
            let zstd = try await client.get("http://127.0.0.1:\(port)/zstd")
            let gzip = try await client.get("http://127.0.0.1:\(port)/gzip")
            #expect(zstd.body == Self.payload && gzip.body == Self.payload)
            var bounded = HTTPClientConfiguration()
            bounded.maxResponseBodyBytes = 1_024
            let small = HTTPClient(configuration: bounded)
            await #expect(throws: HTTPClientError.self) {
                _ = try await small.get("http://127.0.0.1:\(port)/gzip")
            }
            await client.shutdown()
            await small.shutdown()
        }
    }

    @Test(
        "follows same-origin redirects when permitted, refuses loops and filtered targets, and times out"
    )
    func redirectsAndDeadlines() async throws {
        try await Self.withServer { port, _ in
            var permissive = HTTPClientConfiguration()
            permissive.redirectFilter = { _, host, _ in host == "127.0.0.1" }
            let client = HTTPClient(configuration: permissive)
            let redirected = try await client.get("http://127.0.0.1:\(port)/redirect")
            #expect(redirected.body == Array("hello".utf8))
            await #expect(throws: HTTPClientError.redirectRefused("more than 5 redirects")) {
                _ = try await client.get("http://127.0.0.1:\(port)/loop")
            }
            var hasty = HTTPClientConfiguration()
            hasty.requestTimeout = .milliseconds(500)  // the /slow route answers after 5 s
            let impatient = HTTPClient(configuration: hasty)
            await #expect(throws: HTTPClientError.timedOut) {
                _ = try await impatient.get("http://127.0.0.1:\(port)/slow")
            }
            await impatient.shutdown()
            let strict = HTTPClient()  // default filter refuses http:// targets
            await #expect(throws: HTTPClientError.self) {
                _ = try await strict.get("http://127.0.0.1:\(port)/redirect")
            }
            await client.shutdown()
            await strict.shutdown()
        }
    }

    @Test("refused connections surface connectFailed")
    func refusedConnection() async throws {
        let client = HTTPClient()
        await #expect(throws: HTTPClientError.self) {
            _ = try await client.get("http://127.0.0.1:1/")
        }
    }
}
