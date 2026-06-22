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
        .library(name: "HTTPConcurrency", targets: ["HTTPConcurrency"]),
        .library(name: "HTTP1", targets: ["HTTP1"]),
        .library(name: "HPACK", targets: ["HPACK"]),
        .library(name: "HTTP2", targets: ["HTTP2"]),
        .library(name: "WebSocket", targets: ["WebSocket"]),
        .library(name: "HTTPTransport", targets: ["HTTPTransport"]),
        .library(name: "HTTPServer", targets: ["HTTPServer"]),
        .executable(name: "httpd-example", targets: ["httpd-example"]),
    ],
    dependencies: [
        // apple/swift-system — typed, SwiftNIO-free wrappers over POSIX file/socket descriptors,
        // used only by the swift-system transport backbone. Zero external dependencies of its own.
        .package(url: "https://github.com/apple/swift-system.git", from: "1.7.2"),
        // apple/swift-collections — `HeapModule` (the deadline-ordered priority queue behind the
        // deterministic `TestClock` / `AsyncEventProbe`). Linked ONLY by the test-only
        // `HTTPTestSupport` target, so it never enters a downstream consumer's resolved graph. Empty
        // transitive dependency graph; allowed by CLAUDE.md (apple/*).
        .package(url: "https://github.com/apple/swift-collections.git", from: "1.6.0"),
    ],
    targets: [
        // RFC 9110 semantics & currency types, byte primitives, limits, typed errors, Huffman.
        // Zero external dependencies, no I/O — the self-contained substrate every engine builds on.
        .target(
            name: "HTTPCore"
        ),
        .testTarget(
            name: "HTTPCoreTests",
            dependencies: ["HTTPCore", "HTTPTestSupport"]
        ),
        // Shipped-safe concurrency seams: the `TaskProvider` (so untracked `Task { }` spawns become
        // injectable + settle-able) and the `MonotonicNowProvider` (so the HTTP/2 Rapid Reset window
        // is deterministically pinnable). Zero external dependencies, no I/O — reuse-safe.
        .target(
            name: "HTTPConcurrency"
        ),
        .testTarget(
            name: "HTTPConcurrencyTests",
            dependencies: ["HTTPConcurrency", "HTTPTestSupport"]
        ),
        // A tiny C shim exposing process-wide heap-allocation counting (Darwin's `malloc_logger`
        // hook; a no-op elsewhere), backing the `expectAllocations` zero-allocation perf guard.
        // Test/tooling-only; never shipped in an app binary. No dependencies, default C settings.
        .target(name: "CHTTPTestMalloc"),
        // Test-only support: the deterministic async toolkit ported from ADTestKit (TestClock,
        // AsyncEventProbe, AsyncGate, ThreadGate, TaskProviderSpy) plus shared fakes, seeded fuzzing,
        // constrained-stack recursion guards, oracles, and the allocation counter. Linked by every
        // test target. Depends on apple/swift-collections (HeapModule) — confined here, so it never
        // reaches a downstream consumer's graph.
        .target(
            name: "HTTPTestSupport",
            dependencies: [
                "HTTPCore",
                "HTTPConcurrency",
                "HTTPTransport",
                "CHTTPTestMalloc",
                .product(name: "HeapModule", package: "swift-collections"),
            ]
        ),
        .testTarget(
            name: "HTTPTestSupportTests",
            dependencies: ["HTTPTestSupport"]
        ),
        // RFC 9112 — the sans-I/O HTTP/1.1 message parser & serializer (no sockets, no recursion).
        .target(
            name: "HTTP1",
            dependencies: ["HTTPCore"]
        ),
        .testTarget(
            name: "HTTP1Tests",
            dependencies: ["HTTP1", "HTTPTestSupport"]
        ),
        // RFC 7541 — HPACK header compression for HTTP/2: §5.1 prefix integers, §5.2 string literals
        // (with the canonical Huffman code), the static (App. A) & dynamic (§4) tables, and the §6
        // field-representation codec. Sans-I/O; shared canonical Huffman lives in HTTPCore for QPACK.
        .target(
            name: "HPACK",
            dependencies: ["HTTPCore"]
        ),
        .testTarget(
            name: "HPACKTests",
            dependencies: ["HPACK", "HTTPTestSupport"]
        ),
        // RFC 9113 — the sans-I/O HTTP/2 engine: frame layer (§4), connection preface (§3.4),
        // SETTINGS (§6.5), HEADERS field-block + request mapping (§6.2/§8.3) through HPACK, the stream
        // state machine (§5.1), CONTINUATION assembly with the flood guard (§6.10 / CVE-2024-27316),
        // the Rapid Reset defense (CVE-2023-44487), the concurrent-stream cap (§5.1.2), response
        // encoding (HEADERS+DATA), and send-side flow control (§6.9): per-stream + connection send
        // windows, DATA deferred past the window and flushed on WINDOW_UPDATE. Remaining M5 work:
        // receive-side flow control (advertising/replenishing the server's own inbound window).
        .target(
            name: "HTTP2",
            dependencies: ["HTTPCore", "HPACK", "HTTPConcurrency"]
        ),
        .testTarget(
            name: "HTTP2Tests",
            dependencies: ["HTTP2", "HPACK", "HTTPTestSupport"]
        ),
        // M7 (planned) — RFC 9114 (HTTP/3) + RFC 9204 (QPACK) over QUIC. The engine is not built yet;
        // this is a test-only conformance scaffold that carries the h3spec + RFC 9114/9204 catalog so
        // the suite is staged and turns green incrementally as M7 lands. No source target and no product
        // dependency — the catalog is pure data validated with Testing; engine-driven cases are disabled.
        .testTarget(
            name: "HTTP3Tests"
        ),
        // RFC 6455 — the sans-I/O WebSocket engine: the §5.2 frame layer (FIN/RSV/opcode, the
        // 7/16/64-bit payload length, §5.3 masking), close codes (§7.4), and — layered on later — the
        // §4 opening handshake over the HTTP/1.1 Upgrade (and RFC 9220 over HTTP/2). No sockets.
        .target(
            name: "WebSocket",
            dependencies: ["HTTPCore"]
        ),
        .testTarget(
            name: "WebSocketTests",
            dependencies: ["WebSocket", "HTTPTestSupport"]
        ),
        // M3 — the I/O boundary. Four switchable backbones (Network.framework + three POSIX-level
        // variants) behind one abstraction, each isolated in its own subfolder. The only target
        // that performs I/O; the sans-I/O engines never depend on it.
        .target(
            name: "HTTPTransport",
            dependencies: [
                "HTTPCore",
                "HTTPConcurrency",
                .product(name: "SystemPackage", package: "swift-system"),
            ]
        ),
        .testTarget(
            name: "HTTPTransportTests",
            dependencies: ["HTTPTransport", "HTTPTestSupport"]
        ),
        // M4 — the server runtime: wires a transport backbone to the HTTP/1.1 and HTTP/2 engines via
        // an HTTPResponder, fanning connections out across cores and sniffing the protocol (HTTP/2
        // prior-knowledge preface vs an HTTP/1.x request line). The routing DSL layers on top later.
        .target(
            name: "HTTPServer",
            dependencies: ["HTTPCore", "HTTP1", "HTTP2", "HTTPTransport", "HTTPConcurrency"]
        ),
        .testTarget(
            name: "HTTPServerTests",
            dependencies: ["HTTPServer", "HTTP2", "HPACK", "HTTPTestSupport"]
        ),
        // The runnable example server — the executable deliverable. Selects a transport backbone,
        // wires a handful of routes through a ClosureResponder, and serves HTTP/1.1. Drivable with
        // `swift run httpd-example [port] [backbone]` and `curl --http1.1`.
        .executableTarget(
            name: "httpd-example",
            dependencies: ["HTTPCore", "HTTPServer", "HTTPTransport"]
        ),
    ]
)

// Apply the strict settings uniformly to every target we define. Warnings-as-errors is scoped to
// our targets (never dependencies, avoiding the `-suppress-warnings` conflict) and gated by an env
// var so downstream consumers' builds stay green.
let treatWarningsAsErrors = Context.environment["HTTP_WARNINGS_AS_ERRORS"] != nil

for target in package.targets {
    // The C shim (`CHTTPTestMalloc`) has no Swift sources — Swift settings don't apply to it.
    guard target.name != "CHTTPTestMalloc" else { continue }
    var settings = (target.swiftSettings ?? []) + strictSwiftSettings
    if treatWarningsAsErrors {
        settings.append(.treatAllWarnings(as: .error))
    }
    target.swiftSettings = settings
}
