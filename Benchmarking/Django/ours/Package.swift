// swift-tools-version: 6.4
// The HTTP subject for the Django comparison uses the published library with the same
// routes and load generator as Django. Benchmark-only dependencies stay in this package.

import PackageDescription

// Keep the JSON adapter opt-in; both dependencies resolve from their published main branch.
let aemiJSON = Context.environment["BENCH_ADJSON"] != nil

var dependencies: [Package.Dependency] = [
    .package(url: "https://github.com/g-cqd/HTTP.git", branch: "main")
]

if aemiJSON {
    dependencies.append(.package(url: "https://github.com/g-cqd/ADJSON.git", branch: "main"))
}

var benchDependencies: [Target.Dependency] = [
    .product(name: "HTTPCore", package: "HTTP"),
    .product(name: "HTTPServer", package: "HTTP"),
    .product(name: "HTTPTransport", package: "HTTP")
]
var benchSettings: [SwiftSetting] = []

if aemiJSON {
    benchDependencies.append(.product(name: "AemiJSONCore", package: "ADJSON"))
    // The `.adjson` backend in main.swift compiles only under this flag, so the default build has no
    // dangling `import AemiJSONCore`.
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
