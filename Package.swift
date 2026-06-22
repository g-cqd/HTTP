// swift-tools-version: 6.4
//
//  Package.swift — `HTTP`
//  A from-scratch, SwiftNIO-free HTTP/1.1 · HTTP/2 · HTTP/3 server library for Apple platforms.
//
//  Design north star (see Documentation/ and the approved plan):
//    • Sans-I/O protocol engines (pure, allocation-conscious state machines) — testable & fuzzable
//      without sockets; Network.framework is isolated to the `HTTPTransport` target only.
//    • Strict concurrency + strict memory; no force-unwrap / force-cast; no recursion in parsers.
//    • Every parser/validator cites the exact RFC section it implements.
//
//  Targets are introduced milestone-by-milestone (TDD). M0 establishes HTTPCore + tooling.

import PackageDescription

// MARK: - Strict, *reusable-safe* build settings
//
// IMPORTANT: warnings-as-errors is applied to OUR targets only (via the loop below) using the
// first-class `.treatAllWarnings(as:)` setting — NOT `.unsafeFlags` (which would make the package
// unusable as a versioned dependency) and NOT the global `-Xswiftc -warnings-as-errors` (which
// conflicts with the `-suppress-warnings` SwiftPM applies to dependencies like swift-system). It is
// gated behind the `HTTP_WARNINGS_AS_ERRORS` env var so it is OFF for downstream consumers, keeping
// their builds green across toolchains. CI sets the env var. Everything below is reuse-safe.
let strictSwiftSettings: [SwiftSetting] = [
    // complete data-race safety
    .swiftLanguageMode(.v6),
    // SE-0335: existentials must be spelled `any`
    .enableUpcomingFeature("ExistentialAny"),
    // SE-0409: imports are internal unless declared `public import`
    .enableUpcomingFeature("InternalImportsByDefault"),
    // SE-0444: must import modules whose members you use
    .enableUpcomingFeature("MemberImportVisibility"),
    // Lifetime dependencies (`@_lifetime`): let the zero-copy `ByteReader` borrow a `RawSpan`
    // (`~Escapable`) with a *compiler-checked* lifetime instead of an unchecked unsafe pointer.
    // This is a first-class `SwiftSetting`, not `.unsafeFlags`, so it stays reuse-safe downstream.
    .enableExperimentalFeature("Lifetimes"),
]

let package = Package(
    name: "HTTP",
    platforms: [
        .macOS(.v15),  // floor per CLAUDE.md; Synchronization (Mutex/Atomic) needs macOS 15+
        .iOS(.v18),  // floor per CLAUDE.md
    ],
    products: [
        .library(name: "HTTPCore", targets: ["HTTPCore"]),
        .library(name: "HTTP1", targets: ["HTTP1"]),
        .library(name: "HTTPTransport", targets: ["HTTPTransport"]),
        .library(name: "HTTPServer", targets: ["HTTPServer"]),
    ],
    dependencies: [
        // apple/swift-system — typed, SwiftNIO-free wrappers over POSIX file/socket descriptors,
        // used only by the swift-system transport backbone. Zero external dependencies of its own.
        .package(url: "https://github.com/apple/swift-system.git", from: "1.0.0")
    ],
    targets: [
        // RFC 9110 semantics & currency types, byte primitives, limits, typed errors, Huffman.
        // Zero external dependencies, no I/O — the self-contained substrate every engine builds on.
        .target(
            name: "HTTPCore"
        ),
        .testTarget(
            name: "HTTPCoreTests",
            dependencies: ["HTTPCore"]
        ),
        // RFC 9112 — the sans-I/O HTTP/1.1 message parser & serializer (no sockets, no recursion).
        .target(
            name: "HTTP1",
            dependencies: ["HTTPCore"]
        ),
        .testTarget(
            name: "HTTP1Tests",
            dependencies: ["HTTP1"]
        ),
        // M3 — the I/O boundary. Four switchable backbones (Network.framework + three POSIX-level
        // variants) behind one abstraction, each isolated in its own subfolder. The only target
        // that performs I/O; the sans-I/O engines never depend on it.
        .target(
            name: "HTTPTransport",
            dependencies: [
                "HTTPCore",
                .product(name: "SystemPackage", package: "swift-system"),
            ]
        ),
        .testTarget(
            name: "HTTPTransportTests",
            dependencies: ["HTTPTransport"]
        ),
        // M4 — the server runtime: wires a transport backbone to the HTTP/1.1 engine via an
        // HTTPResponder, fanning connections out across cores. The routing DSL layers on top later.
        .target(
            name: "HTTPServer",
            dependencies: ["HTTPCore", "HTTP1", "HTTPTransport"]
        ),
        .testTarget(
            name: "HTTPServerTests",
            dependencies: ["HTTPServer"]
        ),
    ]
)

// Apply the strict settings uniformly to every target we define. Warnings-as-errors is scoped to
// our targets (never dependencies, avoiding the `-suppress-warnings` conflict) and gated by an env
// var so downstream consumers' builds stay green.
let treatWarningsAsErrors = Context.environment["HTTP_WARNINGS_AS_ERRORS"] != nil

for target in package.targets {
    var settings = (target.swiftSettings ?? []) + strictSwiftSettings
    if treatWarningsAsErrors {
        settings.append(.treatAllWarnings(as: .error))
    }
    target.swiftSettings = settings
}
