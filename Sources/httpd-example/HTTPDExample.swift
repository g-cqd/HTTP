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

import Foundation
import HTTPCore
import HTTPServer
import HTTPTransport
import WebSocket

@main
enum HTTPDExample {
    static func main() async {
        // Prefork: HTTPD_WORKERS=N makes this the supervisor (it forks N fresh worker processes and
        // never returns); each worker re-enters here with HTTPD_WORKER set and serves with
        // SO_REUSEPORT so the kernel load-balances across them. POSIX backbones only.
        if !Prefork.isWorker, let workers = Prefork.workerCount {
            Prefork.supervise(workers: workers)
        }
        let port = parsePort()
        let backbone = parseBackbone()
        let tls = makeTLS()
        let configuration = TransportConfiguration(
            host: "127.0.0.1",
            port: port,
            backbone: backbone,
            tls: tls,
            reusePort: Prefork.isWorker
        )
        // A middleware chain (outermost first) wraps the application responder — a stand-in for what a
        // consumer composes; reorder or replace any entry, or add their own `HTTPMiddleware`.
        let responder = MiddlewareChain(
            [
                AccessLogMiddleware { print("httpd-example: \($0)") },  // logs the final exchange
                CompressionMiddleware(),  // gzip the outgoing body
                ServerHeaderMiddleware("httpd-example"),
                DateHeaderMiddleware(),
                SecurityHeadersMiddleware(),
                CORSMiddleware(),
                ConditionalRequestMiddleware()  // ETag on the raw body, If-None-Match → 304
            ],
            terminatingAt: makeResponder()
        )
        // HTTP/3 (RFC 9114): with a TLS identity, run a QUIC transport alongside the TCP one (h3 needs
        // QUIC/TLS); the server advertises it via Alt-Svc (RFC 7838) on the h1/h2 responses so a
        // browser upgrades to h3 on the next request.
        let quicTransport: (any QUICServerTransport)? =
            tls != nil ? QUICTransportFactory.make(configuration) : nil
        let server = HTTPServer(
            transport: TransportFactory.make(configuration),
            responder: responder,
            quicTransport: quicTransport,
            webSocketHandler: makeWebSocketEcho(),
            limits: makeLimits()
        )

        if Prefork.isWorker {
            print("httpd-example: worker \(getpid()) serving on \(port) via \(backbone.rawValue)")
        }
        else if tls == nil {
            print(
                "httpd-example: serving HTTP/1.1 + HTTP/2 (h2c) on http://127.0.0.1:\(port) "
                    + "via \(backbone.rawValue)"
            )
            print("httpd-example: try  curl -v --http2-prior-knowledge http://127.0.0.1:\(port)/")
        }
        else {
            print(
                "httpd-example: serving HTTP/1.1 + HTTP/2 + HTTP/3 over TLS (ALPN + Alt-Svc) on "
                    + "https://127.0.0.1:\(port) via \(backbone.rawValue)"
            )
            print("httpd-example: curl -vk --http2 https://127.0.0.1:\(port)/  (h3: a browser)")
        }
        // Graceful shutdown: SIGTERM/SIGINT stop accepting and drain in-flight connections before the
        // process exits. The prefork master forwards SIGTERM to workers via killpg (Prefork.swift), so
        // each worker drains cleanly; a standalone run drains directly.
        let signalSources = installGracefulShutdown(server)
        defer {
            for source in signalSources { source.cancel() }
        }
        do {
            try await server.run()
        }
        catch {
            print("httpd-example: stopped — \(error)")
        }
    }

    // MARK: Lifecycle

    /// Installs SIGTERM/SIGINT → graceful shutdown, returning the dispatch sources to keep alive.
    ///
    /// The worker (or a standalone run) drains in-flight connections before exiting; the prefork master
    /// already forwards SIGTERM to workers via `killpg` (``Prefork``), so each worker shuts down cleanly.
    private static func installGracefulShutdown(
        _ server: HTTPServer<ContinuousClock>
    ) -> [any DispatchSourceSignal] {
        [SIGTERM, SIGINT]
            .map { number in
                // Disable the default terminate disposition; the dispatch source handles the signal.
                signal(number, SIG_IGN)
                let source = DispatchSource.makeSignalSource(signal: number, queue: .global())
                source.setEventHandler {
                    print("httpd-example: signal \(number) — graceful shutdown")
                    Task { await server.shutdown() }
                }
                source.resume()
                return source
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
                    return text(
                        .ok, "Hello from a from-scratch, NIO-free HTTP/1.1 + HTTP/2 server.\n"
                    )
                case (.get, "/health"):
                    return text(.ok, "OK\n")
                case (.get, "/large"):
                    // A large, compressible body to exercise the gzip middleware (curl --compressed).
                    return text(
                        .ok, String(repeating: "from-scratch swift http server. ", count: 256)
                    )
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
                            ? [.sendText(String(decoding: payload, as: Unicode.UTF8.self))]
                            : [.sendBinary(payload)]
                    default:
                        return []  // Ping is auto-answered by the engine; Pong/Close need no reply
                }
            }
        )
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

    /// Server limits, with an optional `HTTPD_MAX_CONN` env override for benchmarking/tuning.
    ///
    /// The default `maxConnectionsPerClient` (20) is a single-IP DoS guard that a loopback load test
    /// trips; set `HTTPD_MAX_CONN` to raise both the per-client and global caps without recompiling.
    private static func makeLimits() -> HTTPLimits {
        var limits = HTTPLimits.default
        if let raw = ProcessInfo.processInfo.environment["HTTPD_MAX_CONN"], let value = Int(raw) {
            limits.maxConnectionsPerClient = value
            limits.maxConnections = value
        }
        return limits
    }

    // MARK: Argument parsing

    private static func parsePort() -> UInt16 {
        let arguments = CommandLine.arguments
        if arguments.count > 1, let port = UInt16(arguments[1]) {
            return port
        }
        return 8_080
    }

    private static func parseBackbone() -> TransportBackbone {
        let arguments = CommandLine.arguments
        if arguments.count > 2, let backbone = TransportBackbone(rawValue: arguments[2]),
            backbone != .fake
        {
            return backbone
        }
        // Default: swiftSystem leads cleartext throughput (~140k req/s at moderate concurrency). It
        // runs blocking syscalls on a thread per connection, so for very high connection counts or
        // tail-latency-sensitive workloads prefer the async posixKqueue/posixDispatch backbones (lower
        // p99, no thread-per-connection). TLS — and therefore h2-over-TLS and h3 — is honored only by
        // Network.framework, so fall back to it whenever TLS is requested.
        return arguments.contains("tls") ? .networkFramework : .swiftSystem
    }

    /// A throwaway self-signed TLS identity when `tls` appears in the arguments (dev/test only).
    ///
    /// Advertises ALPN `h2` + `http/1.1`, so a `--http2` client negotiates HTTP/2 over TLS
    /// (RFC 9113 §3.3). Honored only by the Network.framework backbone.
    private static func makeTLS() -> TransportTLS? {
        guard CommandLine.arguments.contains("tls") else {
            return nil
        }
        do {
            return try DevTLSIdentity.selfSigned()
        }
        catch {
            print("httpd-example: TLS disabled — \(error)")
            return nil
        }
    }
}
