// swift-tools-version: 6.4
//
//  Package.swift — ours-bench
//
//  The "ours" subject for the Django comparison (Benchmarking/Django/run.sh). A minimal executable that
//  imports the HTTP library from the repo root (path dependency) and serves the SAME routes the Django
//  app mirrors, so the comparison is a same-workload, same-load-generator test. Kept as its OWN package
//  (like Bench/hummingbird) so this throwaway harness never enters the library's consumer dependency
//  graph. Built `-c release` by the harness; debug numbers are fiction.
//
//  It is outside the default build graph, which is exactly how it silently stopped compiling against
//  two breaking library changes (`HTTPLimits`' properties becoming `let`, `TransportFactory.make`
//  becoming throwing). CI now builds it (the `django-bench` job), so the graph it is outside of is no
//  longer the graph that decides whether it works — which means this manifest must resolve with
//  NOTHING but this repository checked out. Two consequences below: the HTTP dependency is named, and
//  the ADJSON sibling is opt-in.
//

import PackageDescription

// ADJSON — a local sibling JSON library, used to investigate whether its tape parser / encoder beats
// Foundation's JSONSerialization for the /json + /echo routes. It is an unpublished sibling checkout
// (`../../../../ADJSON`), so depending on it unconditionally made this package unresolvable anywhere
// that sibling is absent — every CI runner, and every clone that is not a full workspace. Gated behind
// `BENCH_ADJSON`, mirroring how the root manifest gates HTTP_PORTABLE_TLS: the DEFAULT
// graph is this repository alone, and the investigation is one env var away for whoever has the
// sibling. `run.sh` sets it when OURS_JSON=adjson.
let adjson = Context.environment["BENCH_ADJSON"] != nil

var dependencies: [Package.Dependency] = [
    // The library under test, taken straight from the working tree (three levels up).
    //
    // NAMED. Without `name:`, SwiftPM derives the dependency's identity from the checkout directory's
    // basename, so `.product(package: "HTTP")` resolved only when the clone happened to be called
    // `HTTP` — it fails in a git worktree, in a CI workspace named after the repo slug, and in any
    // clone with a different directory name. Benchmarking/Benchmarks/Package.swift already does this.
    .package(name: "HTTP", path: "../../..")
]

if adjson {
    // The Foundation-free `ADJSONCore` product only (tape parse + JSONValue + cursor encode); the
    // umbrella's Codable/Schema/macros are not needed here. ADJSON resolves its own AemiFoundation
    // dependency from github.com/g-cqd@main.
    dependencies.append(.package(path: "../../../../ADJSON"))
}

var benchDependencies: [Target.Dependency] = [
    .product(name: "HTTPCore", package: "HTTP"),
    .product(name: "HTTPServer", package: "HTTP"),
    .product(name: "HTTPTransport", package: "HTTP")
]
var benchSettings: [SwiftSetting] = []

if adjson {
    benchDependencies.append(.product(name: "ADJSONCore", package: "ADJSON"))
    // The `.adjson` backend in main.swift compiles only under this flag, so the default build has no
    // dangling `import ADJSONCore`.
    benchSettings.append(.define("BENCH_ADJSON"))
}

let package = Package(
    name: "ours-bench",
    // Matches the HTTP package floor. SwiftPM refuses to resolve a dependent whose platform floor is
    // below its dependency's, so this is not decoration — it has to track Package.swift's `.macOS`.
    platforms: [.macOS("15.6")],
    dependencies: dependencies,
    targets: [
        .executableTarget(
            name: "ours-bench",
            dependencies: benchDependencies,
            swiftSettings: benchSettings
        )
    ]
)
