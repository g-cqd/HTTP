// swift-tools-version: 6.0
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
// IMPORTANT: we deliberately do NOT bake `-warnings-as-errors` / other `.unsafeFlags` into the
// manifest. `.unsafeFlags` makes a package unusable as a versioned dependency by *other* projects
// (SwiftPM rejects dependencies that carry unsafe flags). Since reusability is a hard requirement,
// warnings-as-errors and sanitizers are enforced in CI via `swift build -Xswiftc -warnings-as-errors`
// instead. Everything below is reuse-safe.
let strictSwiftSettings: [SwiftSetting] = [
    // complete data-race safety
    .swiftLanguageMode(.v6),
    // SE-0335: existentials must be spelled `any`
    .enableUpcomingFeature("ExistentialAny"),
    // SE-0409: imports are internal unless declared `public import`
    .enableUpcomingFeature("InternalImportsByDefault"),
    // SE-0444: must import modules whose members you use
    .enableUpcomingFeature("MemberImportVisibility"),
]

let package = Package(
    name: "HTTP",
    platforms: [
        .macOS("15.6"),  // floor per CLAUDE.md; Synchronization (Mutex/Atomic) needs macOS 15+
        .iOS("18.0"),  // floor per CLAUDE.md
    ],
    products: [
        .library(name: "HTTPCore", targets: ["HTTPCore"])
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
    ]
)

// Apply the strict settings uniformly to every current and future target.
for target in package.targets {
    target.swiftSettings = (target.swiftSettings ?? []) + strictSwiftSettings
}
