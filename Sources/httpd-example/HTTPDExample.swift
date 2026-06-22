//
//  HTTPDExample.swift
//  httpd-example
//
//  A runnable example server — the library's end-to-end deliverable. It selects one of the four
//  transport backbones, wires a small set of routes through a `ClosureResponder` (the result-builder
//  routing DSL will replace this hand-written switch in a later milestone), and serves HTTP/1.1.
//
//  Usage:
//    swift run httpd-example [port] [backbone]
//      port      — TCP port to bind (default 8080)
//      backbone  — networkFramework | posixKqueue | posixDispatch | swiftSystem (default the first)
//
//  Then, in another shell:
//    curl -v --http1.1 http://127.0.0.1:8080/
//    curl -v --http1.1 http://127.0.0.1:8080/health
//    curl -v --http1.1 --data 'ping' http://127.0.0.1:8080/echo
//

import HTTPCore
import HTTPServer
import HTTPTransport

@main
struct HTTPDExample {

    static func main() async {
        let port = parsePort()
        let backbone = parseBackbone()
        let configuration = TransportConfiguration(
            host: "127.0.0.1", port: port, backbone: backbone)
        let server = HTTPServer(
            transport: TransportFactory.make(configuration),
            responder: makeResponder()
        )

        print(
            "httpd-example: serving HTTP/1.1 on http://127.0.0.1:\(port) via \(backbone.rawValue)")
        print("httpd-example: try  curl -v --http1.1 http://127.0.0.1:\(port)/")
        do {
            try await server.run()
        } catch {
            print("httpd-example: stopped — \(error)")
        }
    }

    // MARK: Routing (a plain switch until the routing DSL lands)

    private static func makeResponder() -> ClosureResponder {
        ClosureResponder { request, body in
            switch (request.method, request.path) {
            case (.get, "/"):
                text(.ok, "Hello from a from-scratch, NIO-free HTTP/1.1 server.\n")
            case (.get, "/health"):
                text(.ok, "OK\n")
            case (.post, "/echo"):
                ServerResponse(HTTPResponse(status: .ok), body: body)  // echo the request body
            default:
                text(.notFound, "Not Found\n")
            }
        }
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
}
