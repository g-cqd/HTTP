// swift-tools-version: 6.4
//
//  Package.swift — HTTPBenchmarks
//
//  An *isolated* benchmark package (Ordo `package-benchmark`), deliberately kept OUT of the root
//  manifest so the HTTP library's consumer-facing dependency graph stays at zero external
//  dependencies. SwiftPM has no "dev-only" dependency concept, so a benchmark dependency in the root
//  manifest would land in every consumer's `Package.resolved`; nesting it here avoids that entirely.
//
//  Run from the repository root:
//      swift package --package-path Benchmarks benchmark
//      swift package --package-path Benchmarks benchmark list
//      swift package --package-path Benchmarks benchmark --filter 'http1/*'
//  Live-socket transport benchmarks bind loopback ports, so they need the sandbox disabled:
//      swift package --package-path Benchmarks --disable-sandbox benchmark --filter 'transport/*'
//

import PackageDescription

let package = Package(
    name: "HTTPBenchmarks",
    platforms: [.macOS("15.6")],
    dependencies: [
        .package(name: "HTTP", path: ".."),
        .package(url: "https://github.com/ordo-one/benchmark", from: "1.33.0")
    ],
    targets: [
        .executableTarget(
            name: "HTTPBenchmarks",
            dependencies: [
                .product(name: "HTTPCore", package: "HTTP"),
                .product(name: "HTTP1", package: "HTTP"),
                .product(name: "HPACK", package: "HTTP"),
                .product(name: "HTTP2", package: "HTTP"),
                .product(name: "QPACK", package: "HTTP"),
                .product(name: "HTTP3", package: "HTTP"),
                .product(name: "WebSocket", package: "HTTP"),
                .product(name: "HTTPTransport", package: "HTTP"),
                .product(name: "Benchmark", package: "benchmark")
            ],
            path: "Benchmarks/HTTPBenchmarks",
            // Benchmarks drive `Network`/`NWConnection` clients; Swift 5 mode keeps the harness free of
            // strict-concurrency friction. The library APIs it measures remain Swift 6.
            swiftSettings: [.swiftLanguageMode(.v5)],
            plugins: [
                .plugin(name: "BenchmarkPlugin", package: "benchmark")
            ]
        )
    ]
)
