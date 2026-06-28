// swift-tools-version: 6.0
//
//  Package.swift — ours-bench
//
//  The "ours" subject for the Django comparison (Benchmarking/Django/run.sh). A minimal executable that
//  imports the HTTP library from the repo root (path dependency) and serves the SAME routes the Django
//  app mirrors, so the comparison is a same-workload, same-load-generator test. Kept as its OWN package
//  (like Bench/hummingbird) so this throwaway harness never enters the library's consumer dependency
//  graph. Built `-c release` by the harness; debug numbers are fiction.
//

import PackageDescription

let package = Package(
    name: "ours-bench",
    platforms: [.macOS(.v15)],  // matches the HTTP package floor (Synchronization needs macOS 15+)
    dependencies: [
        // The library under test, taken straight from the working tree (three levels up).
        .package(path: "../../.."),
        // ADJSON — a local sibling JSON library, used (behind BENCH_JSON=adjson) to investigate whether
        // its tape parser / encoder beats Foundation's JSONSerialization for our /json + /echo routes.
        // We depend on the Foundation-free `ADJSONCore` product only (tape parse + JSONValue + cursor
        // encode); the umbrella's Codable/Schema/macros are not needed here. ADJSON resolves its own
        // ADFoundation dependency from a LOCAL checkout when ADFOUNDATION_PATH is exported at build time
        // (run.sh sets it) — keeping this a "locally only" investigation with no network fetch of the
        // AD-family. (swift-collections / swift-syntax still resolve from upstream but, since ADJSONCore
        // doesn't depend on the macro target, swift-syntax is fetched, not compiled.)
        .package(path: "../../../../ADJSON")
    ],
    targets: [
        .executableTarget(
            name: "ours-bench",
            dependencies: [
                .product(name: "HTTPCore", package: "HTTP"),
                .product(name: "HTTPServer", package: "HTTP"),
                .product(name: "HTTPTransport", package: "HTTP"),
                .product(name: "ADJSONCore", package: "ADJSON")
            ]
        )
    ]
)
