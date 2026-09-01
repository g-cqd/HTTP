//
//  main.swift — ours-bench
//
//  The "ours" subject for the Django comparison. Serves the exact routes the Django app mirrors so the
//  two stacks run an identical workload under the same load generator (`oha`). Cleartext HTTP/1.1.
//
//  Usage:  ours-bench [port] [backbone]
//    port      — TCP port to bind (default 8080)
//    backbone  — swiftSystem | posixKqueue | posixDispatch | networkFramework (default swiftSystem)
//
//  Env:
//    BENCH_MIDDLEWARE=1  → wrap the router in the realistic response-shaping chain (gzip, security
//                          headers, CORS, ETag/conditional-GET, Date, Server) that mirrors Django's
//                          MIDDLEWARE list. Unset/0 → bare router (the framework-overhead floor).
//    HTTPD_MAX_CONN=N    → raise the per-client + global connection caps (a loopback load test trips
//                          the default single-IP DoS guard).
//    BENCH_JSON=adjson   → use the ADJSON sibling for /json + /echo. Only available when the package
//                          was BUILT with BENCH_ADJSON set (see Package.swift); otherwise the value is
//                          ignored and Foundation is used, because the dependency is not linked in.
//
//  Routes (mirrored 1:1 by djangoapp/benchsite/views.py):
//    GET  /              → text/plain  "Hello, World!"        (framework floor)
//    GET  /json          → application/json {"message":…}     (serialize a dict, like JsonResponse)
//    GET  /hello/:name   → text/plain, honours ?greeting=     (router + path/query params)
//    POST /echo          → parse JSON body, re-serialize it   (request read + JSON round-trip)
//    GET  /payload       → ~1 KiB text/plain                  (a body worth gzipping, for the chain run)
//

import Foundation
import HTTPCore
import HTTPServer
import HTTPTransport

// The ADJSON sibling is an opt-in dependency (see Package.swift), so its import is too.
#if BENCH_ADJSON
    import ADJSONCore
#endif

// MARK: - Configuration

let arguments = CommandLine.arguments
let port: UInt16 = arguments.count > 1 ? (UInt16(arguments[1]) ?? 8_080) : 8_080
let backbone: TransportBackbone =
    arguments.count > 2 ? (TransportBackbone(rawValue: arguments[2]) ?? .recommended) : .recommended
let useMiddleware = ProcessInfo.processInfo.environment["BENCH_MIDDLEWARE"] == "1"

// A ~1 KiB compressible body for the middleware (gzip) scenario — short bodies fall below gzip's
// minimum-size threshold on both stacks, so the chain run needs a payload worth compressing.
// 32 × 32 B = 1024 B.
let payload = String(repeating: "from-scratch swift http server. ", count: 32)

// MARK: - JSON backend (the ADJSON investigation)
//
// BENCH_JSON=adjson swaps the /json + /echo JSON work from Foundation's JSONSerialization to the local
// ADJSON sibling library (its Foundation-free ADJSONCore: tape parse + cursor re-encode). Both code
// paths are compiled in WHEN the package was built with BENCH_ADJSON; the env var then picks one at
// startup so the harness can A/B the two back-to-back. Without that build flag the ADJSON sibling is
// not a dependency at all (it is an unpublished local checkout — see Package.swift), so the backend
// collapses to Foundation and the enum has one case.

enum JSONBackend: String {
    case foundation
    #if BENCH_ADJSON
        case adjson
    #endif
}

let jsonBackend =
    JSONBackend(rawValue: ProcessInfo.processInfo.environment["BENCH_JSON"] ?? "") ?? .foundation

/// Encode the small `{"message":"Hello, World!"}` object to JSON bytes (the `/json` route).
@inline(__always)
func encodeHelloJSON() -> [UInt8]? {
    switch jsonBackend {
        case .foundation:
            return (try? JSONSerialization.data(withJSONObject: ["message": "Hello, World!"]))
                .map(Array.init)
        #if BENCH_ADJSON
            case .adjson:
                // An order-preserving value serialized straight to UTF-8 bytes (no Foundation).
                let value: JSONValue = .object(["message": .string("Hello, World!")])
                return try? value.encodedBytes()
        #endif
    }
}

/// Parse a JSON request body and re-serialize it (the `/echo` route): the same parse + emit round-trip
/// Django performs with `json.loads(request.body)` + `JsonResponse`.
@inline(__always)
func echoJSON(_ body: [UInt8]) -> [UInt8]? {
    switch jsonBackend {
        case .foundation:
            guard
                let object = try? JSONSerialization.jsonObject(
                    with: Data(body), options: [.fragmentsAllowed]
                ),
                let data = try? JSONSerialization.data(
                    withJSONObject: object, options: [.fragmentsAllowed]
                )
            else {
                return nil
            }
            return Array(data)
        #if BENCH_ADJSON
            case .adjson:
                // Tape-parse, then re-encode from the cursor — no intermediate value tree built.
                guard let document = try? ADJSON.parse(body),
                    let out = try? document.root.encodedBytes()
                else {
                    return nil
                }
                return out
        #endif
    }
}

// MARK: - Routes (mirrored 1:1 by the Django app)

let router = Router {
    Route.get("/") { _, _, _ in .text("Hello, World!") }

    // Serialize a dictionary so we pay the same encode cost Django's JsonResponse does (backend chosen
    // by BENCH_JSON: Foundation JSONSerialization, or the local ADJSON sibling).
    Route.get("/json") { _, _, _ in
        guard let bytes = encodeHelloJSON() else {
            return .status(.internalServerError)
        }
        return .json(bytes)
    }

    // Router + path parameter (:name) + optional ?greeting= query parameter.
    Route.get("/hello/:name") { request, _, context in
        let greeting = request.query["greeting"] ?? "Hello"
        return .text("\(greeting), \(context.parameters["name"] ?? "world")!")
    }

    // Read the request body, parse it as JSON, and re-serialize it — the same work Django's
    // json.loads(request.body) + JsonResponse(...) performs (backend chosen by BENCH_JSON).
    Route.post("/echo") { _, body, _ in
        guard let bytes = echoJSON(await body.collect()) else {
            return .status(.badRequest)
        }
        return .json(bytes)
    }

    // A body large enough to actually exercise gzip in the middleware run.
    Route.get("/payload") { _, _, _ in .text(payload) }
}

// MARK: - Middleware chain (mirrors Django's MIDDLEWARE when BENCH_MIDDLEWARE=1)

let responder: any HTTPResponder

if useMiddleware {
    let chain: [any HTTPMiddleware] = [
        CompressionMiddleware(),  // gzip the outgoing body  ↔ django.middleware.gzip.GZipMiddleware
        ServerHeaderMiddleware("ours-bench"),  // Server header
        DateHeaderMiddleware(),  // Date header
        SecurityHeadersMiddleware(),  // ↔ django.middleware.security.SecurityMiddleware
        CORSMiddleware(),  // ↔ a small CORS middleware on the Django side
        ConditionalRequestMiddleware()  // ETag + If-None-Match → 304  ↔ ConditionalGetMiddleware
    ]
    responder = MiddlewareChain(chain, terminatingAt: router)
}
else {
    responder = router  // bare router: the framework-overhead floor
}

// MARK: - Limits (raise the loopback-tripping connection cap)

// `HTTPLimits` is immutable: its properties are `let` and `with` mutates a `Draft` that the initializer
// then clamps and validates. The same shape Sources/Examples/httpd-example uses.
let limits = HTTPLimits.default.with { draft in
    if let raw = ProcessInfo.processInfo.environment["HTTPD_MAX_CONN"], let value = Int(raw) {
        draft.maxConnectionsPerClient = value
        draft.maxConnections = value
    }
}

// MARK: - Serve

// HTTPD_LOOPS=N → shard the kqueue/epoll backbone across N event loops (audit R4 sweep); nil = auto.
let loopCount = ProcessInfo.processInfo.environment["HTTPD_LOOPS"].flatMap(Int.init)
let configuration = TransportConfiguration(
    host: "127.0.0.1",
    port: port,
    backbone: backbone,
    tls: nil,
    reusePort: false,
    eventLoopCount: loopCount
)
// `TransportFactory.make` is throwing (typed `TransportError`): a bad host, an unbindable port or a
// backbone unavailable on this platform is reported rather than trapped. This is top-level code, so the
// construction joins the run in the same do/catch — a failure here should print the same way a serve
// failure does, not crash the harness mid-matrix.
do {
    let server = HTTPServer(
        transport: try TransportFactory.make(configuration),
        responder: responder,
        limits: limits
    )
    print(
        "ours-bench: serving HTTP/1.1 on http://127.0.0.1:\(port) via \(backbone.rawValue) "
            + "(middleware: \(useMiddleware ? "on" : "off"), json: \(jsonBackend.rawValue))"
    )
    try await server.run()
}
catch {
    print("ours-bench: stopped — \(error)")
}
