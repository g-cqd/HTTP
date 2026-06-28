//
//  main.swift — vapor-bench
//
//  The Vapor baseline for Benchmarking/Bench/run.sh: a minimal Vapor server implementing the shared
//  parity route set (/, /json, /payload, /hello/<name>, POST /echo, /health) so the comparison is a
//  same-workload, same-load-generator test. Port comes from argv[1] (default 8088); Vapor itself is
//  handed a clean argument list so it doesn't try to parse the port as a CLI command.
//

import Vapor

let port = CommandLine.arguments.count > 1 ? (Int(CommandLine.arguments[1]) ?? 8_088) : 8_088
// 32 × 32 B = 1024 B of compressible text.
let payload = String(repeating: "from-scratch swift http server. ", count: 32)

// A clean environment (no argv passthrough) so the bare port argument is not read as a Vapor command;
// production env keeps Vapor's own logging/route-collection overhead minimal.
let app = try await Application.make(Environment(name: "production", arguments: ["vapor"]))
app.logger.logLevel = .error
app.http.server.configuration.hostname = "127.0.0.1"
app.http.server.configuration.port = port

app.get { _ in "Hello from the Vapor baseline.\n" }
app.get("health") { _ in "OK\n" }
app.get("payload") { _ in payload }

app.get("json") { _ in
    Response(
        status: .ok,
        headers: ["Content-Type": "application/json"],
        body: .init(string: #"{"message":"Hello, World!"}"#)
    )
}

app.get("hello", ":name") { request -> String in
    let name = request.parameters.get("name") ?? "world"
    let greeting = (try? request.query.get(String.self, at: "greeting")) ?? "Hello"
    return "\(greeting), \(name)!\n"
}

app.post("echo") { request -> Response in
    let buffer = request.body.data ?? ByteBuffer()
    return Response(
        status: .ok,
        headers: ["Content-Type": "application/json"],
        body: .init(buffer: buffer)
    )
}

try await app.execute()
try await app.asyncShutdown()
