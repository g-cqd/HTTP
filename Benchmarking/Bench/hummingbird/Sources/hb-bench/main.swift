//
//  main.swift — hb-bench
//
//  The in-language SwiftNIO baseline for Benchmarking/Bench/run.sh: a minimal Hummingbird server mirroring
//  httpd-example's routes (`/`, `/health`) so the comparison is a same-workload, same-load-generator
//  test. Logging is left at Hummingbird's default (quiet under load). Port comes from argv[1] (8083).
//

import Hummingbird

let port = CommandLine.arguments.count > 1 ? (Int(CommandLine.arguments[1]) ?? 8_083) : 8_083

let router = Router()

router.get("/") { _, _ in "Hello from the Hummingbird baseline.\n" }
router.get("/health") { _, _ in "OK\n" }

let app = Application(
    router: router,
    configuration: ApplicationConfiguration(
        address: .hostname("127.0.0.1", port: port),
        serverName: "hummingbird"
    )
)

try await app.runService()
