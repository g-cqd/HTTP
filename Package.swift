// swift-tools-version: 6.4
//
//  Package.swift — `HTTP`
//  A from-scratch, SwiftNIO-free HTTP/1.1 · HTTP/2 · HTTP/3 server library for Apple platforms.
//
//  Design north star (see Docs/Documentation/ and the approved plan):
//    • Sans-I/O protocol engines (pure, allocation-conscious state machines) — testable & fuzzable
//      without sockets; Network.framework is isolated to the `HTTPTransport` target only.
//    • Strict concurrency + strict memory; no force-unwrap / force-cast; no recursion in parsers.
//    • Every parser/validator cites the exact RFC section it implements.
//
//  Source layout is tiered for navigability (module names — and therefore imports — are unchanged;
//  only directory paths move, declared per target via `path:`):
//    Sources/Core        — HTTPCore, HTTPConcurrency, CCRC32, CHTTPTestMalloc
//    Sources/Protocols   — HTTP1, HTTP2, HTTP3, HPACK, QPACK, WebSocket
//    Sources/Transport   — HTTPTransport      Sources/Server   — HTTPServer
//    Sources/Testing     — HTTPTestSupport    Sources/Examples — httpd-example

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
    .enableExperimentalFeature("Lifetimes")
]

// G0 — the Darwin-only transport backbones are absent from the Linux build graph, where the portable
// `POSIXEpoll` backbone takes over (the `POSIXSocket` floor, the `PortableTLS` seam, and the `Fake`
// backbone stay cross-platform). `kqueue(2)`, Network.framework (and its QUIC), the Dispatch-sources and
// swift-system backbones all need Darwin/Network, so they are excluded per-platform here rather than
// `#if`-wrapped file-by-file (which would re-indent every body and overflow the line limit); the
// `TransportFactory` cases that name these types are guarded by matching `#if canImport(Darwin)` /
// `#if canImport(Network)`. `#if os(Linux)` is evaluated for the host running SwiftPM — which, since the
// package is built natively per platform and never cross-compiled, is the target platform.
#if os(Linux)
    let darwinOnlyTransportSources = [
        "Network",  // Network.framework backbone (3 files)
        "POSIXKqueue",  // kqueue(2) backbone (3 files)
        "SwiftSystem",  // swift-system + Darwin backbone (2 files)
        "POSIXDispatch/POSIXDispatchConnection.swift",
        "POSIXDispatch/POSIXDispatchTransport.swift",
        "Quic/LegacyQUICConnection.swift",
        "Quic/LegacyQUICStream.swift",
        "Quic/LegacyQUICTransport.swift",
        "Quic/ModernQUICConnection.swift",
        "Quic/ModernQUICStream.swift",
        "Quic/ModernQUICTransport.swift",
        "Quic/QUICTransportFactory.swift"
    ]
    // The outbound/inbound codings built on Apple's `Compression` framework (Brotli RFC 7932, gzip
    // RFC 1952, inflate) — absent on Linux, where the `CompressionMiddleware`/`DecompressionMiddleware`
    // gate them off `#if canImport(Compression)` and zstd (the `CZstd` shim, `HTTP_ZSTD`) is the
    // cross-platform coding. zlib-gzip + `libbrotli` for Linux are a G0 follow-up.
    let appleCompressionSources = [
        "Middleware/Brotli.swift",
        "Middleware/Gzip.swift",
        "Middleware/Inflate.swift"
    ]
    // Test files that exercise the Darwin-only transports (Network.framework + its QUIC) — excluded from
    // the Linux test build, like the backbones they cover. The sans-I/O engine tests, the portable-backbone
    // tests, and the gated PortableTLS suite stay cross-platform.
    let darwinOnlyTransportTestSources = [
        "BackboneConformanceTests.swift",
        "CertificateReloadTests.swift",
        "LegacyQUICTransportTests.swift",
        "LoopbackSupport.swift",
        "ModernQUICTransportTests.swift",
        "NetworkFrameworkMutualTLSTests.swift",
        "NetworkFrameworkTLSTests.swift",
        // raw BSD-socket options; SO_NOSIGPIPE is Darwin-only (the epoll tests cover Linux)
        "POSIXSocketTests.swift"
    ]
    let darwinOnlyServerTestSources = [
        "HTTPServerHTTP3Tests.swift",
        "HTTPServerWebSocketHTTP3Tests.swift"
    ]
    // Tests of the Apple-`Compression` codings (Brotli/gzip/inflate). Excluded on Linux until the
    // zlib/libbrotli Linux codings land (A3); the zstd suite self-gates on `canImport(CZstd)`.
    let appleCompressionTestSources = [
        "CompressionMiddlewareTests.swift",
        "DecompressionMiddlewareTests.swift",
        "DecompressionFuzzTests.swift"
    ]
#else
    let darwinOnlyTransportSources: [String] = []
    let appleCompressionSources: [String] = []
    let darwinOnlyTransportTestSources: [String] = []
    let darwinOnlyServerTestSources: [String] = []
    let appleCompressionTestSources: [String] = []
#endif

// ADFoundation supplies the shared runtime-dispatched SIMD byte kernels (`ADFKernels`) — the WebSocket
// UTF-8 validator uses the ASCII-run skip. Resolved from a local checkout when `ADFOUNDATION_PATH` is
// set (in-repo development), else from git main. This is the one first-party dependency HTTP takes.
func adFoundationDependency() -> Package.Dependency {
    if let path = Context.environment["ADFOUNDATION_PATH"], !path.isEmpty {
        return .package(path: path)
    }
    return .package(url: "https://github.com/g-cqd/ADFoundation.git", branch: "main")
}

let package = Package(
    name: "HTTP",
    platforms: [
        .macOS(.v15),  // floor per CLAUDE.md; Synchronization (Mutex/Atomic) needs macOS 15+
        .iOS(.v18)  // floor per CLAUDE.md
    ],
    products: [
        .library(name: "HTTPCore", targets: ["HTTPCore"]),
        .library(name: "HTTPConcurrency", targets: ["HTTPConcurrency"]),
        .library(name: "HTTP1", targets: ["HTTP1"]),
        .library(name: "HPACK", targets: ["HPACK"]),
        .library(name: "QPACK", targets: ["QPACK"]),
        .library(name: "HTTP2", targets: ["HTTP2"]),
        .library(name: "HTTP3", targets: ["HTTP3"]),
        .library(name: "WebSocket", targets: ["WebSocket"]),
        .library(name: "HTTPTransport", targets: ["HTTPTransport"]),
        .library(name: "HTTPServer", targets: ["HTTPServer"]),
        .library(name: "HTTPObservability", targets: ["HTTPObservability"]),
        .library(name: "HTTPAuth", targets: ["HTTPAuth"]),
        .executable(name: "httpd-example", targets: ["httpd-example"])
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
        // Observability bridges (gap G1) — resolved ONLY by the isolated `HTTPObservability` module,
        // never by a core/protocol/transport/server target, so a consumer of the bare server never pulls
        // them in. All are apple/* or swift-server/* (allowed by CLAUDE.md). swift-metrics records into
        // swift-prometheus' registry for the `/metrics` exposition; swift-log backs the structured access
        // log; swift-distributed-tracing (over swift-service-context) opens a span per request.
        .package(url: "https://github.com/apple/swift-log.git", from: "1.5.0"),
        .package(url: "https://github.com/apple/swift-metrics.git", from: "2.4.0"),
        .package(url: "https://github.com/swift-server/swift-prometheus.git", from: "2.0.0"),
        .package(url: "https://github.com/apple/swift-distributed-tracing.git", from: "1.1.0"),
        .package(url: "https://github.com/apple/swift-service-context.git", from: "1.1.0"),
        // apple/swift-crypto (gap G7) — JWT signature verification in the isolated `HTTPAuth` module:
        // HS256 via `Crypto`'s HMAC, ES256 via P256, RS256 via `_CryptoExtras`' `_RSA`. Confined to
        // `HTTPAuth`, so a bare-server consumer never resolves it (`_CryptoExtras` pulls a BoringSSL
        // graph). apple/* — allowed by CLAUDE.md.
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
        // The one first-party dependency: shared SIMD byte kernels (see `adFoundationDependency`).
        adFoundationDependency()
    ],
    targets: [
        // RFC 9110 semantics & currency types, byte primitives, limits, typed errors, Huffman.
        // Zero external dependencies, no I/O — the self-contained substrate every engine builds on.
        .target(
            name: "HTTPCore",
            dependencies: [
                "CCRC32", .product(name: "ADFKernels", package: "ADFoundation"),
                .product(name: "ADFCore", package: "ADFoundation")
            ],
            path: "Sources/Core/HTTPCore"
        ),
        .testTarget(
            name: "HTTPCoreTests",
            dependencies: ["HTTPCore", "HTTPTestSupport"],
            path: "Tests/Core/HTTPCoreTests"
        ),
        // Shipped-safe concurrency seams: the `TaskProvider` (so untracked `Task { }` spawns become
        // injectable + settle-able) and the `MonotonicNowProvider` (so the HTTP/2 Rapid Reset window
        // is deterministically pinnable). Zero external dependencies, no I/O — reuse-safe.
        .target(
            name: "HTTPConcurrency",
            path: "Sources/Core/HTTPConcurrency"
        ),
        .testTarget(
            name: "HTTPConcurrencyTests",
            dependencies: ["HTTPConcurrency", "HTTPTestSupport"],
            path: "Tests/Core/HTTPConcurrencyTests"
        ),
        // A tiny C shim exposing process-wide heap-allocation counting (Darwin's `malloc_logger`
        // hook; a no-op elsewhere), backing the `expectAllocations` zero-allocation perf guard.
        // Test/tooling-only; never shipped in an app binary. No dependencies, default C settings.
        .target(name: "CHTTPTestMalloc", path: "Sources/Core/CHTTPTestMalloc"),
        // A C shim exposing hardware/SWAR CRC-32 backends for the gzip integrity checksum: the ARMv8
        // CRC32 instructions, zlib's PCLMULQDQ-accelerated `crc32` (the correct x86 hardware path),
        // and a portable slicing-by-8 table. Links the system zlib. Default C settings.
        .target(
            name: "CCRC32",
            path: "Sources/Core/CCRC32",
            linkerSettings: [.linkedLibrary("z")]
        ),
        // A C shim over the system zlib for RFC 7692 permessage-deflate: raw DEFLATE with `Z_SYNC_FLUSH`
        // (the flush mode that frames a WebSocket message, which Apple's Compression cannot express).
        // Keeps the unsafe `z_stream` plumbing in auditable C, like CCRC32. Links the system zlib.
        .target(
            name: "CWSDeflate",
            path: "Sources/Protocols/CWSDeflate",
            linkerSettings: [.linkedLibrary("z")]
        ),
        // G0 — a one-shot gzip (RFC 1952) compress + gzip/zlib/raw inflate C shim over the system zlib,
        // for the Linux content codings (Apple's Compression framework is absent there). Links the system
        // zlib like CCRC32/CWSDeflate; depended on only `.when(platforms: [.linux])`, so it never enters
        // the apple graph (where Darwin Compression backs gzip).
        .target(
            name: "CZlibCoding",
            path: "Sources/Core/CZlibCoding",
            linkerSettings: [.linkedLibrary("z")]
        ),
        // Test-only support: the deterministic async toolkit ported from ADTestKit (TestClock,
        // AsyncEventProbe, AsyncGate, ThreadGate) plus shared fakes, seeded fuzzing,
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
                .product(name: "HeapModule", package: "swift-collections")
            ],
            path: "Sources/Testing/HTTPTestSupport"
        ),
        .testTarget(
            name: "HTTPTestSupportTests",
            dependencies: ["HTTPTestSupport"],
            path: "Tests/Testing/HTTPTestSupportTests"
        ),
        // RFC 9112 — the sans-I/O HTTP/1.1 message parser & serializer (no sockets, no recursion).
        .target(
            name: "HTTP1",
            dependencies: ["HTTPCore"],
            path: "Sources/Protocols/HTTP1"
        ),
        .testTarget(
            name: "HTTP1Tests",
            dependencies: ["HTTP1", "HTTPTestSupport"],
            path: "Tests/Protocols/HTTP1Tests"
        ),
        // RFC 7541 — HPACK header compression for HTTP/2: §5.1 prefix integers, §5.2 string literals
        // (with the canonical Huffman code), the static (App. A) & dynamic (§4) tables, and the §6
        // field-representation codec. Sans-I/O; shared canonical Huffman lives in HTTPCore for QPACK.
        .target(
            name: "HPACK",
            dependencies: ["HTTPCore"],
            path: "Sources/Protocols/HPACK"
        ),
        .testTarget(
            name: "HPACKTests",
            dependencies: ["HPACK", "HTTPTestSupport"],
            path: "Tests/Protocols/HPACKTests"
        ),
        // RFC 9204 — QPACK header compression for HTTP/3. Mirrors HPACK: the §4.1.1 prefix integers,
        // §4.1.2 string literals (the canonical Huffman code, shared from HTTPCore), the 99-entry
        // 0-based static table (App. A), and the §4.5 field-line representations with the §4.5.1
        // encoded field-section prefix. The dynamic table is disabled in v1 (capacity 0, RFC 9204
        // §3.2.2) — static-table + literals only, so RIC is required to be 0. Sans-I/O.
        .target(
            name: "QPACK",
            dependencies: ["HTTPCore"],
            path: "Sources/Protocols/QPACK"
        ),
        .testTarget(
            name: "QPACKTests",
            dependencies: ["QPACK", "HTTPTestSupport"],
            path: "Tests/Protocols/QPACKTests"
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
            dependencies: ["HTTPCore", "HPACK", "HTTPConcurrency"],
            path: "Sources/Protocols/HTTP2"
        ),
        .testTarget(
            name: "HTTP2Tests",
            dependencies: ["HTTP2", "HPACK", "HTTPTestSupport"],
            path: "Tests/Protocols/HTTP2Tests"
        ),
        // RFC 9114 — the sans-I/O HTTP/3 engine: the §7.1 frame layer (varint type+length), the §6.2
        // unidirectional stream-type layer, §7.2.4 SETTINGS (rejecting the reserved HTTP/2 ids), the
        // per-stream connection state machine (control/QPACK singletons, GOAWAY monotonicity, the
        // Rapid-Reset analog), request mapping (§4) through QPACK, and response encoding. Per-stream
        // (QUIC delivers per-stream bytes); the transport owns id allocation. Sans-I/O.
        .target(
            name: "HTTP3",
            dependencies: ["HTTPCore", "QPACK", "HTTPConcurrency"],
            path: "Sources/Protocols/HTTP3"
        ),
        // M7 — the HTTP/3 conformance suite: the h3spec + RFC 9114/9204 catalog (pure data) plus the
        // engine-driven drive-and-assert cases that go live as the engine lands.
        .testTarget(
            name: "HTTP3Tests",
            dependencies: ["HTTP3", "QPACK", "HTTPCore", "HTTPTestSupport"],
            path: "Tests/Protocols/HTTP3Tests"
        ),
        // RFC 6455 — the sans-I/O WebSocket engine: the §5.2 frame layer (FIN/RSV/opcode, the
        // 7/16/64-bit payload length, §5.3 masking), close codes (§7.4), and — layered on later — the
        // §4 opening handshake over the HTTP/1.1 Upgrade (and RFC 9220 over HTTP/2). No sockets.
        .target(
            name: "WebSocket",
            dependencies: [
                "HTTPCore", "CWSDeflate", .product(name: "ADFKernels", package: "ADFoundation")
            ],
            path: "Sources/Protocols/WebSocket"
        ),
        .testTarget(
            name: "WebSocketTests",
            dependencies: ["WebSocket", "HTTPTestSupport"],
            path: "Tests/Protocols/WebSocketTests"
        ),
        // G0 — a C shim re-exporting Linux `<sys/epoll.h>` (the platform `Glibc` module surfaces none of
        // epoll), consumed only by the `POSIXEpoll` backbone. Header-guarded `#if __linux__` (inert
        // elsewhere) and depended on only `.when(platforms: [.linux])`, so it never enters the apple graph.
        .target(name: "CEpoll", path: "Sources/Transport/CEpoll"),
        // M3 — the I/O boundary. Four switchable backbones (Network.framework + three POSIX-level
        // variants) behind one abstraction, each isolated in its own subfolder. The only target
        // that performs I/O; the sans-I/O engines never depend on it.
        .target(
            name: "HTTPTransport",
            dependencies: [
                "HTTPCore",
                "HTTPConcurrency",
                .product(name: "SystemPackage", package: "swift-system"),
                .target(name: "CEpoll", condition: .when(platforms: [.linux]))
            ],
            path: "Sources/Transport/HTTPTransport",
            exclude: darwinOnlyTransportSources
        ),
        .testTarget(
            name: "HTTPTransportTests",
            dependencies: ["HTTPTransport", "HTTPTestSupport"],
            path: "Tests/Transport/HTTPTransportTests",
            exclude: darwinOnlyTransportTestSources
        ),
        // M4 — the server runtime: wires a transport backbone to the HTTP/1.1 and HTTP/2 engines via
        // an HTTPResponder, fanning connections out across cores and sniffing the protocol (HTTP/2
        // prior-knowledge preface vs an HTTP/1.x request line). The routing DSL layers on top later.
        .target(
            name: "HTTPServer",
            dependencies: [
                "HTTPCore", "HTTP1", "HTTP2", "HTTP3", "WebSocket", "HTTPTransport",
                "HTTPConcurrency",
                // Linux gzip coding (zlib); on Darwin gzip is Apple's Compression, so this stays off the graph.
                .target(name: "CZlibCoding", condition: .when(platforms: [.linux]))
            ],
            path: "Sources/Server/HTTPServer",
            exclude: appleCompressionSources
        ),
        .testTarget(
            name: "HTTPServerTests",
            dependencies: [
                "HTTPServer", "HTTP1", "HTTP2", "HTTP3", "HPACK", "QPACK", "WebSocket",
                "HTTPTransport", "HTTPTestSupport",
                .target(name: "CZlibCoding", condition: .when(platforms: [.linux]))
            ],
            path: "Tests/Server/HTTPServerTests",
            exclude: darwinOnlyServerTestSources + appleCompressionTestSources
        ),
        // The runnable example server — the executable deliverable. Selects a transport backbone,
        // wires a handful of routes through a ClosureResponder, and serves HTTP/1.1. Drivable with
        // `swift run httpd-example [port] [backbone]` and `curl --http1.1`.
        .executableTarget(
            name: "httpd-example",
            dependencies: ["HTTPCore", "HTTPServer", "HTTPTransport", "WebSocket"],
            path: "Sources/Examples/httpd-example"
        ),
        // G1 — opt-in observability bridges over the dependency-free `HTTPMetrics` / middleware seams:
        // a swift-metrics sink rendered by swift-prometheus at `/metrics`, a swift-log structured access
        // log, `/healthz` + `/readyz`, and a swift-distributed-tracing span per request. ISOLATED: it
        // depends on HTTPServer one-way, so its dependencies never enter a core consumer's resolved graph
        // — the bridge stays opt-in.
        .target(
            name: "HTTPObservability",
            dependencies: [
                "HTTPServer",
                .product(name: "Logging", package: "swift-log"),
                .product(name: "Metrics", package: "swift-metrics"),
                .product(name: "Prometheus", package: "swift-prometheus"),
                .product(name: "Tracing", package: "swift-distributed-tracing"),
                .product(name: "Instrumentation", package: "swift-distributed-tracing"),
                .product(name: "ServiceContextModule", package: "swift-service-context")
            ],
            path: "Sources/HTTPObservability"
        ),
        .testTarget(
            name: "HTTPObservabilityTests",
            dependencies: [
                "HTTPObservability", "HTTPServer", "HTTPCore",
                .product(name: "Metrics", package: "swift-metrics"),
                .product(name: "Prometheus", package: "swift-prometheus"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "Tracing", package: "swift-distributed-tracing"),
                .product(name: "Instrumentation", package: "swift-distributed-tracing"),
                .product(name: "InMemoryTracing", package: "swift-distributed-tracing"),
                .product(name: "ServiceContextModule", package: "swift-service-context")
            ],
            path: "Tests/Server/HTTPObservabilityTests"
        ),
        // G7 — opt-in auth middlewares (Basic / JWT-Bearer / Forward). ISOLATED so swift-crypto (and its
        // `_CryptoExtras` BoringSSL graph) stays out of a bare-server consumer's resolved graph; it
        // depends on HTTPServer one-way.
        .target(
            name: "HTTPAuth",
            dependencies: [
                "HTTPServer",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto")
            ],
            path: "Sources/HTTPAuth"
        ),
        .testTarget(
            name: "HTTPAuthTests",
            dependencies: [
                "HTTPAuth", "HTTPServer", "HTTPCore",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto")
            ],
            path: "Tests/Server/HTTPAuthTests"
        )
    ],
    // Vendored BoringSSL (ADR 0004 Phase 6) is C++; pin the standard for its `.cc` sources. Only the
    // opt-in `CHTTPBoringSSL` target is C++, so this is inert for the default apple-only graph.
    cxxLanguageStandard: .cxx17
)

// Apply the strict settings uniformly to every target we define. Warnings-as-errors is scoped to
// our targets (never dependencies, avoiding the `-suppress-warnings` conflict) and gated by an env
// var so downstream consumers' builds stay green.
let treatWarningsAsErrors = Context.environment["HTTP_WARNINGS_AS_ERRORS"] != nil

for target in package.targets
where !["CHTTPTestMalloc", "CCRC32", "CEpoll", "CZlibCoding"].contains(target.name) {
    var settings = (target.swiftSettings ?? []) + strictSwiftSettings
    if treatWarningsAsErrors {
        settings.append(.treatAllWarnings(as: .error))
    }
    target.swiftSettings = settings
}

// G0 / ADR 0004 — the opt-in portable TLS backbone (system OpenSSL behind the `CHTTPBoringSSLShims` shim).
// Gated by `HTTP_PORTABLE_TLS` so the DEFAULT build graph stays apple/swiftlang-only — no OpenSSL in a
// consumer's resolved graph unless they opt in. The OpenSSL prefix is `HTTP_OPENSSL_PREFIX` or the
// Homebrew `openssl@3` default on macOS (Linux: set the env, or rely on the default search paths).
// Appended after the strict loop above so the C shim never receives Swift-only settings. The portable
// Swift sources / tests guard on `#if canImport(CHTTPBoringSSLShims)`, so they vanish when the flag is off.
if Context.environment["HTTP_PORTABLE_TLS"] != nil {
    // Vendored, symbol-prefixed (`CHTTPBoringSSL_*`) BoringSSL — no system OpenSSL, no
    // `HTTP_OPENSSL_PREFIX` (ADR 0004 Phase 6). The C/C++/asm sources compile in-tree; SwiftPM links
    // libc++ for the C++ `.cc`. The whole block stays gated on `HTTP_PORTABLE_TLS`, so the default build
    // graph is apple-only.
    package.targets.append(
        .target(
            name: "CHTTPBoringSSL",
            path: "Sources/Core/CHTTPBoringSSL",
            cSettings: [
                .define("_GNU_SOURCE"),
                .define("_POSIX_C_SOURCE", to: "200112L"),
                .define("_DARWIN_C_SOURCE")
            ]
        )
    )
    // The hand-written macro-wrapper shim — the only place that includes the BoringSSL umbrella and holds
    // the unsafe interop. Depends on the vendored module.
    package.targets.append(
        .target(
            name: "CHTTPBoringSSLShims",
            dependencies: ["CHTTPBoringSSL"],
            path: "Sources/Core/CHTTPBoringSSLShims",
            cSettings: [.define("_GNU_SOURCE")]
        )
    )
    // The transport (and its tests) consume both the vendored module (prefixed BoringSSL symbols) and the
    // shim (the macro wrappers). No link flags or header search paths needed — the vendored module carries
    // its own headers via its modulemap.
    for target in package.targets
    where ["HTTPTransport", "HTTPTransportTests"].contains(target.name) {
        target.dependencies.append("CHTTPBoringSSL")
        target.dependencies.append("CHTTPBoringSSLShims")
    }
}

// The opt-in outbound `zstd` content coding (RFC 8878): a `CZstd` C shim over the system libzstd,
// since Apple's Compression framework has no Zstandard codec. Gated by `HTTP_ZSTD` so the DEFAULT
// build graph never links libzstd; the Swift integration (Zstd.swift, the CompressionMiddleware
// case, the test) all guard on `#if canImport(CZstd)`, so they vanish when the flag is off. The
// libzstd prefix is `HTTP_ZSTD_PREFIX` or the Homebrew `zstd` default on macOS (Linux: set the env,
// or rely on the default search paths). Appended after the strict loop above so the C shim never
// receives Swift-only settings — mirrors the HTTP_PORTABLE_TLS block. The `.unsafeFlags` header /
// library paths are acceptable here precisely because the whole block is opt-in (off for downstream
// consumers), exactly like the gated settings the package already documents.
if Context.environment["HTTP_ZSTD"] != nil {
    let zstdPrefix = Context.environment["HTTP_ZSTD_PREFIX"] ?? "/opt/homebrew/opt/zstd"
    let zstdInclude = zstdPrefix + "/include"
    let zstdLib = zstdPrefix + "/lib"
    // The thin C wrapper over <zstd.h>. It alone needs the header path; it links libzstd directly,
    // so a consumer of HTTPServer pulls the dependency transitively. Default C settings — the loop
    // above (which it is appended after) never gives a C target Swift-only settings.
    package.targets.append(
        .target(
            name: "CZstd",
            path: "Sources/Core/CZstd",
            cSettings: [.unsafeFlags(["-I", zstdInclude])],
            linkerSettings: [
                .unsafeFlags(["-L", zstdLib]),
                .linkedLibrary("zstd")
            ]
        )
    )
    // The server (and its tests) gain the shim dependency, plus the clang header path threaded
    // through swiftc (`-Xcc -I …`) so importing the `CZstd` module resolves regardless of the
    // toolchain's default search paths.
    for target in package.targets
    where ["HTTPServer", "HTTPServerTests"].contains(target.name) {
        target.dependencies.append("CZstd")
        var settings = target.swiftSettings ?? []
        // The joined `-I<path>` form (one token after `-Xcc`) — the separated `-Xcc -I -Xcc <path>`
        // form interleaves with swift-testing's plugin args on the test target and breaks its build.
        settings.append(.unsafeFlags(["-Xcc", "-I" + zstdInclude]))
        target.swiftSettings = settings
    }
}

// The opt-in Brotli content coding (RFC 7932) on the non-Apple path: a `CBrotli` C shim over libbrotli,
// since Apple's Compression (which backs `br` on Darwin) is absent on Linux. Gated by `HTTP_BROTLI` so the
// DEFAULT build graph never links libbrotli; the Swift side (BrotliLinux + the `br` arms of
// CompressionMiddleware/InflateLinux/DecompressionMiddleware) guards on `#if canImport(CBrotli)`. The
// libbrotli prefix is `HTTP_BROTLI_PREFIX` (the Homebrew `brotli` default on macOS; set it to `/usr` on a
// Linux distro). Mirror of the HTTP_ZSTD block above.
if Context.environment["HTTP_BROTLI"] != nil {
    let brotliPrefix = Context.environment["HTTP_BROTLI_PREFIX"] ?? "/opt/homebrew/opt/brotli"
    let brotliInclude = brotliPrefix + "/include"
    let brotliLib = brotliPrefix + "/lib"
    package.targets.append(
        .target(
            name: "CBrotli",
            path: "Sources/Core/CBrotli",
            cSettings: [.unsafeFlags(["-I", brotliInclude])],
            linkerSettings: [
                .unsafeFlags(["-L", brotliLib]),
                .linkedLibrary("brotlienc"),
                .linkedLibrary("brotlidec"),
                .linkedLibrary("brotlicommon")
            ]
        )
    )
    for target in package.targets
    where ["HTTPServer", "HTTPServerTests"].contains(target.name) {
        target.dependencies.append("CBrotli")
        var settings = target.swiftSettings ?? []
        settings.append(.unsafeFlags(["-Xcc", "-I" + brotliInclude]))
        target.swiftSettings = settings
    }
}
