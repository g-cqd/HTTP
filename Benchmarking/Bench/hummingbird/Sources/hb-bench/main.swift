//
//  main.swift — hb-bench
//
//  The in-language SwiftNIO baseline for Benchmarking/Bench/run.sh: a minimal Hummingbird server that
//  implements the shared parity route set (/, /json, /payload, /hello/<name>, POST /echo, /health) so
//  the comparison is a same-workload, same-load-generator test. Deliberately its OWN package so SwiftNIO
//  and the Hummingbird stack never enter the HTTP library's dependency graph. Port from argv[1] (8083).
//

import Hummingbird

let port = CommandLine.arguments.count > 1 ? (Int(CommandLine.arguments[1]) ?? 8_083) : 8_083
// 32 × 32 B = 1024 B of compressible text.
let payload = String(repeating: "from-scratch swift http server. ", count: 32)

let router = Router()

router.get("/") { _, _ in "Hello from the Hummingbird baseline.\n" }
router.get("/health") { _, _ in "OK\n" }
router.get("/payload") { _, _ in payload }

router.get("/json") { _, _ in
    EditedResponse(
        headers: [.contentType: "application/json"],
        response: #"{"message":"Hello, World!"}"#
    )
}

router.get("/hello/:name") { request, context in
    let name = context.parameters.get("name") ?? "world"
    let greeting = request.uri.queryParameters["greeting"].map(String.init) ?? "Hello"
    return "\(greeting), \(name)!\n"
}

router.post("/echo") { request, _ in
    let buffer = try await request.body.collect(upTo: 1 << 20)
    var response = Response(status: .ok, body: .init(byteBuffer: buffer))
    response.headers[.contentType] = "application/json"
    return response
}

let app = Application(
    router: router,
    configuration: ApplicationConfiguration(
        address: .hostname("127.0.0.1", port: port),
        serverName: "hummingbird"
    )
)

try await app.runService()
