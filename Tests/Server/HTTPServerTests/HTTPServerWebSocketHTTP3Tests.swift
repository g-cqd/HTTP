//
//  HTTPServerWebSocketHTTP3Tests.swift
//  HTTPServerTests
//
//  Drives WebSocket-over-HTTP/3 (RFC 9220) end-to-end over a real Network.framework QUIC loopback: an
//  Extended CONNECT (`:protocol = websocket`) plus a masked WebSocket text frame in an h3 DATA frame go
//  in; a `:status = 200` and the echoed frame as a DATA frame on the same stream must come back —
//  mirroring `HTTPServerWebSocketHTTP2Tests` over the real-QUIC harness of `HTTPServerHTTP3Tests`.
//

import Foundation
import HTTP3
import HTTPCore
import HTTPTransport
import Network
import QPACK
import Testing
import WebSocket

@testable import HTTPServer

@Suite("HTTPServer — WebSocket over HTTP/3 (RFC 9220)")
struct HTTPServerWebSocketHTTP3Tests {
    @Test(
        "Extended CONNECT upgrades to WebSocket and echoes a text frame", .timeLimit(.minutes(1)))
    func webSocketOverHTTP3() async throws {
        let echo = ClosureWebSocketHandler { event in
            guard case .message(let opcode, let payload) = event, opcode == .text else {
                return []
            }
            return [.sendText(String(decoding: payload, as: Unicode.UTF8.self))]
        }
        let tls = try DevTLSIdentity.selfSigned(applicationProtocols: ["h3"])
        let transport = LegacyQUICTransport(
            configuration: TransportConfiguration(
                host: "127.0.0.1", port: 0, backbone: .networkFramework, tls: tls
            )
        )
        let connections = try await transport.start()
        let port = transport.boundPort
        let server = HTTPServer(
            transport: TransportFactory.make(TransportConfiguration(port: 0, backbone: .fake)),
            responder: Router { Route.webSocket("/chat", handler: echo) }
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

        let (status, tunnel) = try await Self.tunnelEcho(port: port, text: "hi")
        #expect(status == "200")  // the tunnel was accepted (RFC 9220 / RFC 8441 §5)
        // The echoed WebSocket frame rides an h3 DATA frame: unmasked text "hi".
        #expect(Self.containsSubsequence(tunnel, [0x81, 0x02, 0x68, 0x69]))
    }

    // MARK: A minimal WebSocket-over-HTTP/3 client over Network.framework QUIC

    /// Opens a QUIC stream, sends an Extended CONNECT and one masked WS text frame (no FIN), then reads
    /// back the `:status` and the concatenated tunnel DATA until the server's echoed frame appears.
    private static func tunnelEcho(
        port: UInt16, text: String
    ) async throws -> (status: String?, tunnel: [UInt8]) {
        let connection = NWConnection(
            host: "127.0.0.1",
            port: NWEndpoint.Port(rawValue: port) ?? .any,
            using: clientParameters()
        )
        defer { connection.cancel() }
        try await ready(connection)

        let section = QPACKEncoder()
            .encode([
                HeaderField(name: ":method", value: "CONNECT"),
                HeaderField(name: ":protocol", value: "websocket"),
                HeaderField(name: ":scheme", value: "https"),
                HeaderField(name: ":authority", value: "127.0.0.1"),
                HeaderField(name: ":path", value: "/chat")
            ])
        // Pipeline the Extended CONNECT HEADERS and the first masked WS frame (in a DATA frame), no FIN —
        // the tunnel stays open.
        var wire = frame(0x01, section)
        wire += frame(0x00, maskedText(text))
        try await send(wire, on: connection)

        let echoed: [UInt8] = [0x81, UInt8(text.utf8.count)] + Array(text.utf8)
        return try await receiveTunnel(connection, until: echoed)
    }

    /// Reads chunks until the decoded tunnel DATA contains `needle` (the echoed frame) with a `200`, or
    /// the stream ends.
    private static func receiveTunnel(
        _ connection: NWConnection, until needle: [UInt8]
    ) async throws -> (status: String?, tunnel: [UInt8]) {
        var buffer: [UInt8] = []
        while true {
            let chunk = try await receiveChunk(connection)
            buffer.append(contentsOf: chunk.bytes)
            let decoded = try decodeTunnel(buffer)
            if decoded.status == "200", containsSubsequence(decoded.tunnel, needle) {
                return decoded
            }
            if chunk.done {
                return decoded
            }
        }
    }

    /// Decodes the `:status` (from the accept HEADERS) and the concatenated DATA-frame payloads (the
    /// tunnel bytes) from a possibly-partial buffer; an incomplete trailing frame is left for the next read.
    private static func decodeTunnel(_ bytes: [UInt8]) throws -> (status: String?, tunnel: [UInt8])
    {
        var status: String?
        var tunnel: [UInt8] = []
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
                        tunnel.append(contentsOf: next.payload)
                    default:
                        break
                }
            }
        }
        return (status, tunnel)
    }

    private static func clientParameters() -> NWParameters {
        let options = NWProtocolQUIC.Options(alpn: ["h3"])
        options.initialMaxStreamsUnidirectional = 8
        options.initialMaxStreamsBidirectional = 8
        sec_protocol_options_set_verify_block(
            options.securityProtocolOptions,
            { _, _, complete in complete(true) },  // accept the self-signed dev cert (test only)
            DispatchQueue(label: "ws.h3.test.verify")
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

    /// A client-masked WebSocket text frame (RFC 6455 §5.2 — client→server frames are masked).
    private static func maskedText(_ text: String) -> [UInt8] {
        let payload = Array(text.utf8)
        let key: [UInt8] = [0x11, 0x22, 0x33, 0x44]
        var frame: [UInt8] = [0x81, 0x80 | UInt8(payload.count)]
        frame += key
        for (index, byte) in payload.enumerated() { frame.append(byte ^ key[index & 0x3]) }
        return frame
    }

    private static func containsSubsequence(_ haystack: [UInt8], _ needle: [UInt8]) -> Bool {
        guard needle.count <= haystack.count, !needle.isEmpty else {
            return false
        }
        for start in 0 ... (haystack.count - needle.count)
        where Array(haystack[start ..< start + needle.count]) == needle {
            return true
        }
        return false
    }

    private static func ready(_ connection: NWConnection) async throws {
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
            connection.start(queue: DispatchQueue(label: "ws.h3.test.client"))
        }
    }

    private static func send(_ bytes: [UInt8], on connection: NWConnection) async throws {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, any Error>) in
            connection.send(
                content: Data(bytes),
                contentContext: .defaultMessage,
                isComplete: false,  // keep the stream open — the tunnel is bidirectional
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

    private static func receiveChunk(
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
