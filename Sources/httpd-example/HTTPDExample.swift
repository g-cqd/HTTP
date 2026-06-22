//
//  HTTPDExample.swift
//  httpd-example
//
//  A runnable example server — the library's end-to-end deliverable. It selects one of the four
//  transport backbones, wires a small set of routes through a `ClosureResponder` (the result-builder
//  routing DSL will replace this hand-written switch in a later milestone), and serves both HTTP/1.1
//  and HTTP/2 cleartext (h2c, prior knowledge) on the same port — the server sniffs the protocol.
//
//  Usage:
//    swift run httpd-example [port] [backbone]
//      port      — TCP port to bind (default 8080)
//      backbone  — networkFramework | posixKqueue | posixDispatch | swiftSystem (default the first)
//
//  Then, in another shell:
//    curl -v --http1.1 http://127.0.0.1:8080/
//    curl -v --http2-prior-knowledge http://127.0.0.1:8080/
//    curl -v --http2-prior-knowledge --data 'ping' http://127.0.0.1:8080/echo
//

import HTTPCore
import HTTPServer
import HTTPTransport
import WebSocket

@main
struct HTTPDExample {

    static func main() async {
        let port = parsePort()
        let backbone = parseBackbone()
        let tls = makeTLS()
        let configuration = TransportConfiguration(
            host: "127.0.0.1", port: port, backbone: backbone, tls: tls)
        let server = HTTPServer(
            transport: TransportFactory.make(configuration),
            responder: makeResponder(),
            webSocketHandler: makeWebSocketEcho()
        )

        if tls == nil {
            print(
                "httpd-example: serving HTTP/1.1 + HTTP/2 (h2c) on http://127.0.0.1:\(port) "
                    + "via \(backbone.rawValue)")
            print("httpd-example: try  curl -v --http2-prior-knowledge http://127.0.0.1:\(port)/")
        } else {
            print(
                "httpd-example: serving HTTP/1.1 + HTTP/2 over TLS (ALPN) on "
                    + "https://127.0.0.1:\(port) via \(backbone.rawValue)")
            print("httpd-example: try  curl -vk --http2 https://127.0.0.1:\(port)/")
        }
        do {
            try await server.run()
        } catch {
            print("httpd-example: stopped — \(error)")
        }
    }

    // MARK: Routing (a plain switch until the routing DSL lands)

    private static func makeResponder() -> ClosureResponder {
        ClosureResponder { request, body in
            // HEAD is GET without a body; the server strips the body, so route the two together
            // (RFC 9110 §9.3.2).
            let method: HTTPMethod = request.method == .head ? .get : request.method
            switch (method, request.path) {
            case (.get, "/"):
                return text(.ok, "Hello from a from-scratch, NIO-free HTTP/1.1 + HTTP/2 server.\n")
            case (.get, "/health"):
                return text(.ok, "OK\n")
            case (.post, "/echo"):
                return ServerResponse(HTTPResponse(status: .ok), body: body)  // echo the body
            default:
                return text(.notFound, "Not Found\n")
            }
        }
    }

    /// A WebSocket echo handler on `/ws` (RFC 6455): every text/binary message is sent straight back.
    private static func makeWebSocketEcho() -> ClosureWebSocketHandler {
        ClosureWebSocketHandler(
            shouldUpgrade: { $0.path == "/ws" },
            handle: { event in
                switch event {
                case .message(let opcode, let payload):
                    return opcode == .text
                        ? [.sendText(String(decoding: payload, as: UTF8.self))]
                        : [.sendBinary(payload)]
                default:
                    return []  // Ping is auto-answered by the engine; Pong/Close need no reply
                }
            })
    }

    /// Builds a `text/plain` response (RFC 9110 §8.3) carrying `message`.
    private static func text(_ status: HTTPStatus, _ message: String) -> ServerResponse {
        var fields = HTTPFields()
        fields.append("text/plain; charset=utf-8", for: .contentType)
        return ServerResponse(
            HTTPResponse(status: status, headerFields: fields),
            body: Array(message.utf8)
        )
    }

    // MARK: Argument parsing

    private static func parsePort() -> UInt16 {
        let arguments = CommandLine.arguments
        if arguments.count > 1, let port = UInt16(arguments[1]) { return port }
        return 8080
    }

    private static func parseBackbone() -> TransportBackbone {
        let arguments = CommandLine.arguments
        if arguments.count > 2, let backbone = TransportBackbone(rawValue: arguments[2]),
            backbone != .fake
        {
            return backbone
        }
        return .networkFramework
    }

    /// A throwaway self-signed TLS identity when `tls` appears in the arguments (dev/test only).
    ///
    /// Advertises ALPN `h2` + `http/1.1`, so a `--http2` client negotiates HTTP/2 over TLS
    /// (RFC 9113 §3.3). Honored only by the Network.framework backbone.
    private static func makeTLS() -> TransportTLS? {
        guard CommandLine.arguments.contains("tls") else { return nil }
        do {
            return try DevTLSIdentity.selfSigned()
        } catch {
            print("httpd-example: TLS disabled — \(error)")
            return nil
        }
    }
}
