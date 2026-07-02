//
//  HTTPServerHTTP3Tests.swift
//  HTTPServerTests
//
//  The M7 end-to-end acceptance: a real Network.framework QUIC client performs an HTTP/3 (RFC 9114)
//  GET over the legacy QUIC transport against the live server, and gets the responder's reply back —
//  exercising the whole stack (LegacyQUICTransport → serveHTTP3 → HTTP3Connection → QPACK → responder
//  → response framing) over loopback. (`curl --http3` is unavailable, so a Network.framework client is
//  the acceptance.)
//

import Foundation
import HTTP3
import HTTPCore
import HTTPTransport
import Network
import QPACK
import Testing

@testable import HTTPServer

@Suite("HTTP/3 server — loopback")
struct HTTPServerHTTP3Tests {
    @Test(
        "an HTTP/3 GET over the legacy QUIC backbone returns the response", .timeLimit(.minutes(1)))
    func http3GetLegacy() async throws {
        let tls = try DevTLSIdentity.selfSigned(applicationProtocols: ["h3"])
        let (status, body) = try await serveAndGet(
            transport: LegacyQUICTransport(
                configuration: TransportConfiguration(
                    host: "127.0.0.1", port: 0, backbone: .networkFramework, tls: tls
                )
            ),
            responder: helloResponder()
        )
        #expect(status == "200")
        #expect(body == Array("hello h3".utf8))
    }

    @Test(
        "an HTTP/3 client cannot spoof the client-cert subject (audit P0-1)",
        .timeLimit(.minutes(1)))
    func http3StripsSpoofedClientCertSubject() async throws {
        let tls = try DevTLSIdentity.selfSigned(applicationProtocols: ["h3"])
        // Echo back the verified client-cert subject the handler reads from the context (or `<none>`).
        let echo = ClosureResponder { _, _, context in
            let subject = context.connection.tlsPeerSubject ?? "<none>"
            return ServerResponse(HTTPResponse(status: .ok), body: Array(subject.utf8))
        }
        let (status, body) = try await serveAndGet(
            transport: LegacyQUICTransport(
                configuration: TransportConfiguration(
                    host: "127.0.0.1", port: 0, backbone: .networkFramework, tls: tls
                )
            ),
            responder: echo,
            extraHeaders: [HeaderField(name: "x-client-cert-subject", value: "attacker")]
        )
        #expect(status == "200")
        // The dev TLS presents no client certificate, so the verified subject is nil; the spoofed
        // inbound header is ignored — the handler reads no subject from the context.
        #expect(body == Array("<none>".utf8))
    }

    @Test(
        "an HTTP/3 GET over the modern QUIC backbone returns the response", .timeLimit(.minutes(1)))
    func http3GetModern() async throws {
        guard #available(macOS 26, iOS 26, *) else {
            return
        }
        let tls = try DevTLSIdentity.selfSigned(applicationProtocols: ["h3"])
        let (status, body) = try await serveAndGet(
            transport: ModernQUICTransport(
                configuration: TransportConfiguration(
                    host: "127.0.0.1", port: 0, backbone: .networkFramework, tls: tls
                )
            ),
            responder: helloResponder()
        )
        #expect(status == "200")
        #expect(body == Array("hello h3".utf8))
    }

    @Test(
        "a native HTTP/3 streamed response is delivered chunk-by-chunk over QUIC (P6b)",
        .timeLimit(.minutes(1)))
    func http3StreamingLegacy() async throws {
        let tls = try DevTLSIdentity.selfSigned(applicationProtocols: ["h3"])
        // A `.streaming` responder drives the native path (respondHeaders → H3StreamWriter DATA frames
        // → empty FIN); the client reassembles the two chunks into the full body.
        let streaming = ClosureResponder { request, _, _ in
            #expect(request.method == .get)
            return .streaming(contentType: "text/plain") { writer in
                try await writer.write(Array("hello ".utf8))
                try await writer.write(Array("h3".utf8))
            }
        }
        let (status, body) = try await serveAndGet(
            transport: LegacyQUICTransport(
                configuration: TransportConfiguration(
                    host: "127.0.0.1", port: 0, backbone: .networkFramework, tls: tls
                )
            ),
            responder: streaming
        )
        #expect(status == "200")
        #expect(body == Array("hello h3".utf8))
    }

    @Test(
        "a streaming HTTP/3 route receives its request body as a stream end-to-end (Phase 1.4)",
        .timeLimit(.minutes(1)))
    func http3StreamingRequest() async throws {
        let tls = try DevTLSIdentity.selfSigned(applicationProtocols: ["h3"])
        // `.streamingBody()` drives the true-incremental path (requestHead → requestBodyChunk →
        // requestEnd → handler stream); the handler reports it received a stream and the byte count.
        let router = Router {
            Route.post("/upload") { _, body, _ in
                .text("streaming=\(body.isStreaming) bytes=\(await body.collect().count)")
            }
            .streamingBody()
        }
        let (status, body) = try await serveAndPost(
            transport: LegacyQUICTransport(
                configuration: TransportConfiguration(
                    host: "127.0.0.1", port: 0, backbone: .networkFramework, tls: tls
                )
            ),
            responder: router,
            path: "/upload",
            body: Array("hello".utf8)
        )
        #expect(status == "200")
        #expect(String(decoding: body, as: Unicode.UTF8.self) == "streaming=true bytes=5")
    }

    /// A buffered responder returning `hello h3` — the default for the plain-GET acceptance tests.
    private func helloResponder() -> any HTTPResponder {
        ClosureResponder { request, _, _ in
            #expect(request.method == .get)
            return ServerResponse(HTTPResponse(status: .ok), body: Array("hello h3".utf8))
        }
    }

    /// Starts `transport`, drives the HTTP/3 server over it, and performs one GET, returning the reply.
    private func serveAndGet(
        transport: any QUICServerTransport,
        responder: any HTTPResponder,
        extraHeaders: [HeaderField] = []
    ) async throws -> (status: String?, body: [UInt8]) {
        let connections = try await transport.start()
        let port = transport.boundPort
        let server = HTTPServer(
            transport: try TransportFactory.make(TransportConfiguration(port: 0, backbone: .fake)),
            responder: responder
        )
        let serving = Task {
            await withDiscardingTaskGroup { group in
                for await connection in connections {
                    group.addTask { await server.serveHTTP3(connection) }
                }
            }
        }
        defer {
            serving.cancel()
            Task { await transport.shutdown() }
        }
        return try await get(port: port, path: "/", extraHeaders: extraHeaders)
    }

    /// Starts `transport`, drives the HTTP/3 server over it, and performs one POST carrying `body`.
    private func serveAndPost(
        transport: any QUICServerTransport,
        responder: any HTTPResponder,
        path: String,
        body: [UInt8]
    ) async throws -> (status: String?, body: [UInt8]) {
        let connections = try await transport.start()
        let port = transport.boundPort
        let server = HTTPServer(
            transport: try TransportFactory.make(TransportConfiguration(port: 0, backbone: .fake)),
            responder: responder
        )
        let serving = Task {
            await withDiscardingTaskGroup { group in
                for await connection in connections {
                    group.addTask { await server.serveHTTP3(connection) }
                }
            }
        }
        defer {
            serving.cancel()
            Task { await transport.shutdown() }
        }
        return try await post(port: port, path: path, body: body)
    }

    // MARK: A minimal HTTP/3 client over Network.framework QUIC

    private func get(
        port: UInt16, path: String, extraHeaders: [HeaderField] = []
    ) async throws -> (status: String?, body: [UInt8]) {
        let connection = NWConnection(
            host: "127.0.0.1",
            port: NWEndpoint.Port(rawValue: port) ?? .any,
            using: Self.clientParameters()
        )
        defer { connection.cancel() }
        try await ready(connection)

        let section = QPACKEncoder()
            .encode(
                [
                    HeaderField(name: ":method", value: "GET"),
                    HeaderField(name: ":scheme", value: "https"),
                    HeaderField(name: ":authority", value: "127.0.0.1"),
                    HeaderField(name: ":path", value: path)
                ] + extraHeaders
            )
        try await sendComplete(Self.frame(0x01, section), on: connection)  // HEADERS + FIN
        let response = try await receiveAll(from: connection)
        return try Self.decode(response)
    }

    private func post(
        port: UInt16, path: String, body: [UInt8]
    ) async throws -> (status: String?, body: [UInt8]) {
        let connection = NWConnection(
            host: "127.0.0.1",
            port: NWEndpoint.Port(rawValue: port) ?? .any,
            using: Self.clientParameters()
        )
        defer { connection.cancel() }
        try await ready(connection)

        let section = QPACKEncoder()
            .encode([
                HeaderField(name: ":method", value: "POST"),
                HeaderField(name: ":scheme", value: "https"),
                HeaderField(name: ":authority", value: "127.0.0.1"),
                HeaderField(name: ":path", value: path)
            ])
        var wire = Self.frame(0x01, section)  // HEADERS
        wire += Self.frame(0x00, body)  // DATA
        try await sendComplete(wire, on: connection)  // HEADERS + DATA + FIN
        let response = try await receiveAll(from: connection)
        return try Self.decode(response)
    }

    private static func clientParameters() -> NWParameters {
        let options = NWProtocolQUIC.Options(alpn: ["h3"])
        // Permit the server's control + QPACK unidirectional streams (RFC 9114 §6.2).
        options.initialMaxStreamsUnidirectional = 8
        options.initialMaxStreamsBidirectional = 8
        // Accept the self-signed dev certificate for this loopback test only.
        sec_protocol_options_set_verify_block(
            options.securityProtocolOptions,
            { _, _, complete in complete(true) },
            DispatchQueue(label: "h3.test.verify")
        )
        return NWParameters(quic: options)
    }

    private static func frame(_ type: UInt64, _ payload: [UInt8]) -> [UInt8] {
        var out: [UInt8] = []
        QUICVarint.encode(type, into: &out)
        QUICVarint.encode(UInt64(payload.count), into: &out)
        out.append(contentsOf: payload)
        return out
    }

    private static func decode(_ bytes: [UInt8]) throws -> (status: String?, body: [UInt8]) {
        var status: String?
        var body: [UInt8] = []
        try bytes.withUnsafeBytes { raw in
            var reader = ByteReader(raw)
            let frames = HTTP3FrameDecoder(maxFrameSize: 1 << 20)
            while let next = try frames.nextFrame(&reader) {
                switch next.type {
                    case .headers:
                        let fields = try next.payload.withUnsafeBytes {
                            try QPACKDecoder().decode($0.bytes)
                        }
                        for field in fields where field.name == ":status" { status = field.value }
                    case .data:
                        body.append(contentsOf: next.payload)
                    default:
                        break
                }
            }
        }
        return (status, body)
    }

    private func ready(_ connection: NWConnection) async throws {
        let queue = DispatchQueue(label: "h3.test.client")
        let resumed = OnceLatch()
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, any Error>) in
            connection.stateUpdateHandler = { state in
                switch state {
                    case .ready where resumed.take():
                        continuation.resume()
                    case .failed(let error) where resumed.take():
                        continuation.resume(throwing: error)
                    default:
                        break
                }
            }
            connection.start(queue: queue)
        }
    }

    private func sendComplete(_ bytes: [UInt8], on connection: NWConnection) async throws {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, any Error>) in
            connection.send(
                content: Data(bytes),
                contentContext: .finalMessage,
                isComplete: true,
                completion: .contentProcessed { error in
                    if let error {
                        continuation.resume(throwing: error)
                    }
                    else {
                        continuation.resume()
                    }
                }
            )
        }
    }

    private func receiveAll(from connection: NWConnection) async throws -> [UInt8] {
        var all: [UInt8] = []
        while true {
            let chunk = try await receiveChunk(connection)
            all.append(contentsOf: chunk.bytes)
            if chunk.done {
                return all
            }
        }
    }

    private func receiveChunk(
        _ connection: NWConnection
    ) async throws -> (bytes: [UInt8], done: Bool) {
        try await withCheckedThrowingContinuation { continuation in
            connection.receive(minimumIncompleteLength: 1, maximumLength: 65_535) {
                data, _, isComplete, error in
                if let error {
                    continuation.resume(throwing: error)
                }
                else {
                    continuation.resume(returning: ([UInt8](data ?? Data()), isComplete))
                }
            }
        }
    }
}
