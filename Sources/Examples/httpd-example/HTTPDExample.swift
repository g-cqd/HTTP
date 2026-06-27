//
//  HTTPDExample.swift
//  httpd-example
//
//  A runnable example server — the library's end-to-end deliverable. It selects one of the four
//  transport backbones, wires its routes through the result-builder ``Router`` DSL behind a middleware
//  chain (metrics, gzip, security headers, CORS, conditional GET, Range), and serves HTTP/1.1 and
//  HTTP/2 cleartext (h2c, prior knowledge) on the same port — the server sniffs the protocol — plus
//  HTTP/3 when run with `tls`.
//
//  Usage:
//    swift run httpd-example [port] [backbone] [tls]
//      port      — TCP port to bind (default 8080)
//      backbone  — networkFramework | posixKqueue | posixDispatch | swiftSystem (default swiftSystem)
//
//  Then, in another shell:
//    curl -v --http1.1 http://127.0.0.1:8080/
//    curl -v http://127.0.0.1:8080/hello/world          # a :name path parameter
//    curl -v --range 0-31 http://127.0.0.1:8080/large   # 206 Partial Content (RangeMiddleware)
//    curl -v http://127.0.0.1:8080/metrics              # the HTTPMetrics seam
//    curl -v --http2-prior-knowledge --data 'ping' http://127.0.0.1:8080/echo
//    curl -v -H 'Accept: text/html' http://127.0.0.1:8080/negotiate  # content negotiation (§12.5)
//

import Foundation
import HTTPCore
import HTTPServer
import HTTPTransport
import Synchronization
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
        // A middleware chain (outermost first) wraps the responder — reorder/replace/add freely.
        // HTTPD_QUIET drops the per-request access-log `print` (it dominates under load) — the fair
        // posture for the Bench/ comparison against logging-off reference servers.
        let quiet = ProcessInfo.processInfo.environment["HTTPD_QUIET"] != nil
        let metrics = ExampleMetrics()  // the HTTPMetrics seam, surfaced at GET /metrics below
        var middlewares: [any HTTPMiddleware] = []
        if !quiet {
            middlewares.append(AccessLogMiddleware { print("httpd-example: \($0)") })
        }
        middlewares.append(
            contentsOf: [
                MetricsMiddleware(metrics),  // RED signals over the whole chain (outermost timing)
                DecompressionMiddleware(),  // inbound: gunzip a gzip body (bomb-capped)
                CompressionMiddleware(),  // gzip the outgoing body
                ServerHeaderMiddleware("httpd-example"),
                DateHeaderMiddleware(),
                SecurityHeadersMiddleware(),
                CORSMiddleware(),
                ConditionalRequestMiddleware(),  // ETag on the raw body, If-None-Match → 304
                RangeMiddleware()  // innermost: Range → 206 (§14)
            ] as [any HTTPMiddleware]
        )
        let responder = MiddlewareChain(middlewares, terminatingAt: makeRouter(metrics: metrics))
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

    // MARK: Routing (the result-builder DSL)

    /// Builds the route table with the ``Router`` DSL — the real routing surface, replacing the old
    /// hand-written switch.
    ///
    /// Demonstrates static routes, a `:name` path parameter, a body echo, and surfacing the metrics
    /// seam. `HEAD` is served by the matching `GET` (RFC 9110 §9.3.2); an unknown path is 404 and a
    /// known path with the wrong method is 405 — both folded by the router.
    private static func makeRouter(metrics: ExampleMetrics) -> Router {
        Router {
            Route.get("/") { _, _, _ in
                .text("Hello from a from-scratch, NIO-free HTTP/1.1 + HTTP/2 + HTTP/3 server.\n")
            }
            Route.get("/health") { _, _, _ in .text("OK\n") }
            // A `:name` path parameter (RFC 3986 §3.3) plus an optional `?greeting=` query parameter.
            Route.get("/hello/:name") { request, parameters, _ in
                let greeting = request.query["greeting"] ?? "Hello"
                return .text("\(greeting), \(parameters["name"] ?? "world")!\n")
            }
            // A large, compressible, range-able body — exercises CompressionMiddleware (curl
            // --compressed) and RangeMiddleware (curl -r 0-31 → 206 Partial Content).
            Route.get("/large") { _, _, _ in
                .text(String(repeating: "from-scratch swift http server. ", count: 256))
            }
            // Echo the request body straight back.
            Route.post("/echo") { _, _, body in
                ServerResponse(HTTPResponse(status: .ok), body: body)
            }
            // Surfaces the HTTPMetrics seam the MetricsMiddleware feeds (rate + errors).
            Route.get("/metrics") { _, _, _ in .text(metrics.snapshot()) }
            // Proactive content negotiation (RFC 9110 §12.5): JSON or HTML per `Accept`, greeting
            // localized per `Accept-Language`, `Vary` set, 406 when neither type fits. See
            // ``ContentNegotiation``.
            ContentNegotiation.route()
            // A trailing `*path` catch-all capturing the remaining path (RFC 3986 §3.3).
            Route.get("/files/*path") { _, parameters, _ in
                .text("would serve: \(parameters["path"] ?? "")\n")
            }
            // A route group: `/api/*` share a prefix and a scoped access log (per-group middleware).
            RouteGroup(
                "/api",
                middleware: [AccessLogMiddleware { print("httpd-example[api]: \($0)") }]
            ) {
                Route.get("/ping") { _, _, _ in .text("pong\n") }
                Route.get("/echo/:message") { _, parameters, _ in
                    .text("\(parameters["message"] ?? "")\n")
                }
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
