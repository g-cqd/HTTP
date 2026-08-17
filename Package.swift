// swift-tools-version: 6.4
//
//  Package.swift — `HTTP`
//  A from-scratch, SwiftNIO-free HTTP/1.1 · HTTP/2 · HTTP/3 server library for Apple platforms.
//
//  Design north star (see docs/ and the approved plan):
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

// SE-0458 strict memory safety — the STAGED gate (ADR 0009, superseding ADR 0002's all-or-nothing
// deferral). The compiler flags every expression that "uses unsafe constructs but is not marked with
// `unsafe`"; the package has 465 such sites, so flipping it on globally would not compile. Instead it is
// enabled per target for the targets that are ALREADY at zero, where it costs nothing today and buys a
// hard ratchet tomorrow: under `HTTP_WARNINGS_AS_ERRORS`, the first un-annotated unsafe expression added
// to one of these targets is a BUILD ERROR, not a warning someone scrolls past.
//
// The remaining targets are held by a counted budget instead (`scripts/strict-memory-safety.py` +
// `.github/strict-memory-safety-budget.tsv`, run by the `strict-memory-safety` CI job): their counts may
// fall, never rise. A target reaches zero, moves into this list, and stops being a number.
//
// Adding a target here is a one-line change once its count hits 0 — that is the whole point of staging.
let strictMemorySafeTargets: Set<String> = [
    "HTTPConcurrency",  // 1 site annotated (the CLOCK_MONOTONIC read)
    "HPACK",  // 2 sites annotated (RFC 7541 §5.2 string materialization)
    "QPACK",  // 2 sites annotated (RFC 9204 §4.1.2 string materialization)
    "HTTPObservability",  // already 0 — pure bridge code over the metrics/log/trace seams
    "HTTPAuth"  // already 0 — pure crypto/middleware over swift-crypto
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
        // The `NWEndpoint` -> `TransportAddress` mapping only. `Quic/QUICPeer.swift` — the
        // `unattributed` sentinel the admission gate and `RateLimitIdentity` key on (ADD-P0.5b) — is
        // platform-neutral and deliberately STAYS in the Linux graph.
        "Quic/QUICPeer+Network.swift",
        "Quic/QUICTransportFactory.swift"
    ]
    // The outbound/inbound codings built on Apple's `Compression` framework (Brotli RFC 7932, gzip
    // RFC 1952, inflate) — absent on Linux, where the `CompressionMiddleware`/`DecompressionMiddleware`
    // gate them off `#if canImport(Compression)` and zstd (the `CZstd` shim, the `Zstd` trait) is the
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
        // FLAKE-1's `_dispatch_queue_xref_dispose` trap, which is a property of
        // `POSIXDispatchTransport` — itself Darwin-only and excluded above. No debt: there is no
        // libdispatch accept source on Linux to get this wrong.
        "AcceptShutdownRaceTests.swift",
        "BackboneConformanceTests.swift",
        "CertificateReloadTests.swift",
        "LegacyQUICTransportTests.swift",
        // The three `assertLoopback*` round-trips, each driving an `NWConnection` through
        // `NetworkFrameworkConnection`. The raw `socket(2)`/`connect(2)` dialer that used to sit
        // beside them needs none of that and now lives in `LoopbackDialer.swift`, which is NOT
        // excluded — it was the last thing keeping `AcceptBackpressureTests` off this platform.
        "LoopbackSupport.swift",
        "ModernQUICTransportTests.swift",
        "NetworkFrameworkMutualTLSTests.swift",
        "NetworkFrameworkTLSTests.swift",
        // The wire oracle for QUIC application close codes: an `NWConnection` h3 client reading the
        // peer's close code — Network.framework end to end, like the QUIC backbones it observes.
        "QUICApplicationCloseProbe.swift",
        // Network.framework QUIC listeners + `NWConnection` h3 clients + the `NWEndpoint` overload
        // of `QUICPeer.address(of:)`. The platform-neutral half of the same contract — the shared,
        // capped bucket every unattributable peer folds into — is `QUICPeerAdmissionTests.swift`,
        // which is NOT excluded and keeps ADD-P0.5b covered on Linux.
        "QUICPeerAttributionTests.swift",
        // raw BSD-socket options; SO_NOSIGPIPE is Darwin-only (the epoll tests cover Linux)
        "POSIXSocketTests.swift",
        // Built on `KqueueEventLoop` + `POSIXKqueueConnection`, both excluded above, so it cannot
        // compile here. This was recorded as the largest coverage debt in this list, because the
        // single-slot-waiter defect it proves is not a kqueue defect — `POSIXEpollConnection` carried
        // the same `OnceResumer` shape and `EpollEventLoop` the same readiness tables.
        //
        // **That debt is retired**, so the entry stays but the warning does not. Its connection-level
        // claims are now covered portably, and with strictly more, by
        // `ConnectionDirectionOwnershipTests` (an `#if` picks the reactor and raw connection; N-way
        // 2/4/8, close, half-close, EPIPE, cancellation, descriptor reuse), and its two loop-level
        // claims have a native Linux twin in `EpollEventLoopTests`. Both run on Linux; neither is
        // excluded. Keep it that way — an exclusion here is honest only while something else covers
        // the behaviour on the platform being excluded.
        "ReadinessWaiterCollisionTests.swift"
    ]
    // Everything `HTTPServerTests` drops on Linux: the Network.framework-provided HTTP/3 suites, and
    // the tests of codings Apple's `Compression` backs (Brotli/gzip/inflate). One list rather than two
    // because it gates ONE target and the reason for each entry belongs to the entry, not to the list
    // name — the zstd suite self-gates on `canImport(CZstd)` instead.
    //
    // `ContentEncoderStreamTests` and `StreamingCompressionTests` are NOT here any more. They were,
    // because `GzipEncoder.makeStream()` returned nil off Darwin and every streamed response fell
    // through to identity — the exclusion was a symptom of a missing feature, not a portability
    // defect in the tests. The feature exists now (`ZlibDeflateStream` over the `CZlibCoding` shim's
    // resumable `deflate`), so both suites run here, and their byte-identity case is what holds the
    // Linux streamed and buffered codings to the same octets. Keep it that way.
    let serverTestExclusions = [
        "HTTPServerHTTP3Tests.swift",
        "HTTPServerWebSocketHTTP3Tests.swift",
        "CompressionMiddlewareTests.swift",
        "DecompressionMiddlewareTests.swift",
        "DecompressionFuzzTests.swift",
        "DecompressionPolicyTests.swift",
        "InflateBoundsTests.swift"
    ]
#else
    let darwinOnlyTransportSources: [String] = []
    let appleCompressionSources: [String] = []
    let darwinOnlyTransportTestSources: [String] = []
    let serverTestExclusions: [String] = []
#endif

// MARK: - Opt-in system-library codings (SE-0450 package traits)
//
// The `Zstd` / `Brotli` content codings link system libraries (libzstd / libbrotli) the default
// graph must never reference, so they are opt-in via SE-0450 package traits — a consumer writes
// `.package(url: …, from: …, traits: ["Zstd"])`; a local build passes `--traits Zstd,Brotli`.
// These replace the retired `HTTP_ZSTD` / `HTTP_BROTLI` env-var gates: an env var is invisible to
// SwiftPM's resolver (a consumer could not opt in through a versioned dependency at all), while a
// trait is part of the manifest contract.
//
// Mechanics (probed 2026-08-17 on the pinned Swift 6.4 toolchain): a trait cannot conditionally
// DECLARE a target — every declared root-package target compiles under the default build, and the
// manifest cannot observe traits. So the two C shims below are always declared, and the trait
// instead conditions everything else: their `.c` bodies compile to EMPTY translation units unless
// the trait-conditional `.define(…, .when(traits:))` is active, and every `-I`/`-L`/`-l` — including
// `.linkedLibrary(_:_, .when(traits:))` — is trait-conditional, so a default build on a machine
// without libzstd/libbrotli succeeds and never sees either library. The Swift consumers' dependency
// edges are `.when(traits:)`-conditional, so their `#if canImport(CZstd)` / `#if canImport(CBrotli)`
// guards flip with the trait, unchanged.
//
// The include/lib prefixes are path HINTS, not gates: `HTTP_ZSTD_PREFIX` / `HTTP_BROTLI_PREFIX`
// override them, defaulting to the Homebrew kegs on macOS and to nothing on Linux (the distro dev
// packages land on the default search paths, where a redundant `-I /usr/include` would only reorder
// system headers). The `.unsafeFlags` they feed are trait-conditional and verified (same probe) to
// neither apply to nor poison a stable-versioned consumer's default (trait-off) resolution.
#if os(macOS)
    let zstdPrefix: String? = Context.environment["HTTP_ZSTD_PREFIX"] ?? "/opt/homebrew/opt/zstd"
    let brotliPrefix: String? =
        Context.environment["HTTP_BROTLI_PREFIX"] ?? "/opt/homebrew/opt/brotli"
#else
    let zstdPrefix: String? = Context.environment["HTTP_ZSTD_PREFIX"]
    let brotliPrefix: String? = Context.environment["HTTP_BROTLI_PREFIX"]
#endif

/// An always-declared coding-shim target whose every setting is trait-conditional: the
/// `HTTP_TRAIT_*` define that un-empties the translation unit, the `-I`/`-L` search paths when a
/// prefix hint exists, and the `-l` links — all absent from a default (trait-off) build.
func codingShim(
    name: String, path: String, trait: String, define: String, libraries: [String], prefix: String?
) -> Target {
    var cSettings: [CSetting] = [.define(define, .when(traits: [trait]))]
    var linkerSettings: [LinkerSetting] = []
    if let prefix {
        cSettings.append(.unsafeFlags(["-I", prefix + "/include"], .when(traits: [trait])))
        linkerSettings.append(.unsafeFlags(["-L", prefix + "/lib"], .when(traits: [trait])))
    }
    linkerSettings += libraries.map { .linkedLibrary($0, .when(traits: [trait])) }
    return .target(name: name, path: path, cSettings: cSettings, linkerSettings: linkerSettings)
}

// ADFoundation supplies the shared runtime-dispatched SIMD byte kernels (`ADFKernels`) — the WebSocket
// UTF-8 validator uses the ASCII-run skip. This is the one first-party dependency HTTP takes.
//
// Pinned to an exact reviewed revision, not `branch: "main"` (2026-07-31 audit). A moving branch means
// two checkouts of the same HTTP commit can resolve different dependency code, so a build is not
// reproducible, a benchmark result is not attributable, and a CI green is not evidence about any
// particular input. `Package.resolved` stays gitignored on purpose — this is a reusable library and its
// consumers must resolve their own graph — so this pin is what makes *this* package's own builds
// deterministic. Note the scope honestly: the rest of the graph is version-ranged and still floats
// within its ranges; only this first-party, unversioned dependency is nailed down here.
//
// To advance it: review the target revision, update the constant below, delete `Package.resolved`, and
// re-resolve.
let adFoundationRevision = "35a7356cde384b7880c79d9a1f4d250f4a3123a2"

func adFoundationDependency() -> Package.Dependency {
    .package(url: "https://github.com/Aemi-Studio/aemi.git", revision: adFoundationRevision)
}

let package = Package(
    name: "HTTP",
    platforms: [
        // 15.6, not `.v15`. CLAUDE.md, README.md ("macOS 15.6+ / iOS 18+") and
        // Benchmarking/Benchmarks/Package.swift (`.macOS("15.6")`) all say 15.6; this manifest was the
        // only place claiming 15.0, and it is the one place a consumer actually reads. A manifest that
        // advertises a floor nothing builds or tests against is a promise the project has not made:
        // resolution would succeed on 15.0 and the failure would land at the consumer's build, not
        // here. Synchronization (Mutex/Atomic) needs 15.0 at minimum, so this is a raise, not a claim
        // about what the code strictly requires — the documented, tested floor is what ships.
        .macOS("15.6"),  // floor per CLAUDE.md
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
    // SE-0450 package traits — the opt-in system-library codings (see the MARK above for the full
    // mechanics). Neither is a default trait: the default graph stays free of libzstd/libbrotli.
    traits: [
        // RFC 8878 `zstd` content coding via the `CZstd` shim over the system libzstd
        // (Homebrew `zstd` on macOS, `libzstd-dev` on Debian/Ubuntu).
        .trait(name: "Zstd", description: "The RFC 8878 zstd coding over the system libzstd."),
        // RFC 7932 `br` content coding on the non-Apple path via the `CBrotli` shim over libbrotli
        // (Darwin gets `br` from Apple's Compression framework without this trait).
        .trait(name: "Brotli", description: "The RFC 7932 br coding over libbrotli (non-Apple).")
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
        // them in. All are apple/* (per the dependency policy). swift-metrics records into the module's
        // own `PrometheusRegistry` for the `/metrics` text exposition (0.0.4, in-house — swift-prometheus
        // left the graph); swift-log backs the structured access log; swift-distributed-tracing (over
        // swift-service-context) opens a span per request.
        .package(url: "https://github.com/apple/swift-log.git", from: "1.5.0"),
        .package(url: "https://github.com/apple/swift-metrics.git", from: "2.4.0"),
        .package(url: "https://github.com/apple/swift-distributed-tracing.git", from: "1.1.0"),
        .package(url: "https://github.com/apple/swift-service-context.git", from: "1.1.0"),
        // apple/swift-crypto (gap G7) — every keyed primitive on a security boundary. Two products,
        // deliberately scoped differently:
        //   `Crypto`         — `HTTPServer` (the session cookie's HMAC-SHA256) and `HTTPAuth` (JWT
        //                      HS256 + the Basic-auth blinded comparison). Reaching a bare-server
        //                      consumer is the accepted cost of not shipping in-house SHA-256/HMAC on
        //                      a signing path.
        //   `_CryptoExtras`  — `HTTPAuth` ONLY (RS256 via `_RSA`). It pulls a BoringSSL graph, so it
        //                      stays confined to the module that actually needs RSA.
        // apple/* — allowed by CLAUDE.md.
        //
        // 4.0.0, not 3.0.0, and the floor is load-bearing for LINUX rather than for any API we call.
        // On Darwin `Crypto` is `@_exported import CryptoKit` (its `SymmetricKeys.swift` opens with
        // `#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API`), and CryptoKit's
        // `SymmetricKey` is `Sendable` in the SDK — so every `Sendable` type holding one compiles
        // here and the gap is invisible. On Linux the same import resolves to swift-crypto's own
        // `SymmetricKey`, which through 3.15.1 is declared `public struct SymmetricKey:
        // ContiguousBytes` with NO `Sendable`. `SessionSigningKeys` (a `Sendable` struct holding
        // two) and `BasicAuthMiddleware.fixedCredentialVerifier` (which captures one in an
        // `@Sendable` closure) are therefore Darwin-only code by accident.
        // swift-crypto 4.0.0 declares `public struct SymmetricKey: ContiguousBytes, Sendable` over a
        // `struct SecureBytes: @unchecked Sendable` — the conformance reviewed and asserted UPSTREAM,
        // by the people who own the invariant, which is the only place an `@unchecked` on someone
        // else's storage can honestly be written. Taking the bump is why neither call site needs a
        // local wrapper or a `@preconcurrency` import.
        // The major bump costs nothing here: swift-crypto declares no `platforms:` floor in any of
        // 3.15.1/4.x, so this does not touch the macOS 15.6 / iOS 18 deployment floor, and the whole
        // API surface this package uses (`SymmetricKey`, `HMAC<SHA256>`, `SHA256.Digest.byteCount`,
        // `P256.Signing.PublicKey`/`ECDSASignature`, `_RSA.Signing.PublicKey`/`RSASignature`) is
        // unchanged across the 4.0 boundary, whose sole release note is the WWDC25 refresh.
        .package(url: "https://github.com/apple/swift-crypto.git", from: "4.0.0"),
        // The one first-party dependency: shared SIMD byte kernels (see `adFoundationDependency`).
        adFoundationDependency()
    ],
    targets: [
        // RFC 9110 semantics & currency types, byte primitives, limits, typed errors, Huffman.
        // Zero external dependencies, no I/O — the self-contained substrate every engine builds on.
        // No crypto either: the keyed primitives it used to host (SHA-256/HMAC/HKDF) live on the
        // session and JWT signing boundaries, so they moved to swift-crypto in `HTTPServer`/`HTTPAuth`
        // rather than being carried here. `RandomToken` needs none — `SystemRandomNumberGenerator`
        // draws from the platform CSPRNG.
        .target(
            name: "HTTPCore",
            dependencies: [
                "CCRC32", .product(name: "AemiKernels", package: "aemi"),
                .product(name: "AemiKernel", package: "aemi")
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
        // CRC32 instructions, an in-house CPUID-dispatched PCLMULQDQ folding kernel on x86, and a
        // portable slicing-by-8 table. Self-contained — with the former zlib borrow gone, HTTPCore's
        // unconditional graph links no system libraries. Default C settings.
        .target(
            name: "CCRC32",
            path: "Sources/Core/CCRC32"
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
        // The RFC 8878 `zstd` content coding shim over the system libzstd (Apple's Compression
        // framework has no Zstandard codec, on any platform). Opt-in via the `Zstd` package trait:
        // the target is always DECLARED (a trait cannot conditionally declare one — see the traits
        // MARK), but trait-off it compiles to an empty translation unit and contributes no
        // `-I`/`-L`/`-lzstd`, so the default graph never references libzstd.
        codingShim(
            name: "CZstd",
            path: "Sources/Core/CZstd",
            trait: "Zstd",
            define: "HTTP_TRAIT_ZSTD",
            libraries: ["zstd"],
            prefix: zstdPrefix
        ),
        // The RFC 7932 `br` content coding shim over libbrotli for the non-Apple path (Darwin's `br`
        // is Apple's Compression framework). Opt-in via the `Brotli` package trait; same
        // always-declared / empty-TU-when-off mechanics as `CZstd` above.
        codingShim(
            name: "CBrotli",
            path: "Sources/Core/CBrotli",
            trait: "Brotli",
            define: "HTTP_TRAIT_BROTLI",
            libraries: ["brotlienc", "brotlidec", "brotlicommon"],
            prefix: brotliPrefix
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
                "HTTPCore", "CWSDeflate", .product(name: "AemiKernels", package: "aemi")
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
                // The session cookie's HMAC-SHA256 is a security boundary, so it uses the audited
                // first-party implementation rather than an in-house one (see the `swift-crypto`
                // dependency comment). `Crypto` only — never `_CryptoExtras`.
                .product(name: "Crypto", package: "swift-crypto"),
                // Linux gzip coding (zlib); on Darwin gzip is Apple's Compression, so this stays off the graph.
                .target(name: "CZlibCoding", condition: .when(platforms: [.linux])),
                // The opt-in codings: trait-conditional edges, so `#if canImport(CZstd)` /
                // `#if canImport(CBrotli)` in the middleware flip with the trait.
                .target(name: "CZstd", condition: .when(traits: ["Zstd"])),
                .target(name: "CBrotli", condition: .when(traits: ["Brotli"]))
            ],
            path: "Sources/Server/HTTPServer",
            exclude: appleCompressionSources
        ),
        .testTarget(
            name: "HTTPServerTests",
            dependencies: [
                "HTTPServer", "HTTP1", "HTTP2", "HTTP3", "HPACK", "QPACK", "WebSocket",
                "HTTPTransport", "HTTPTestSupport",
                .target(name: "CZlibCoding", condition: .when(platforms: [.linux])),
                // The self-gating coding suites (`#if canImport(CZstd)` / `#if canImport(CBrotli)`)
                // compile only when the trait puts the shim in the graph.
                .target(name: "CZstd", condition: .when(traits: ["Zstd"])),
                .target(name: "CBrotli", condition: .when(traits: ["Brotli"]))
            ],
            path: "Tests/Server/HTTPServerTests",
            exclude: serverTestExclusions
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
        // a swift-metrics sink rendered by the in-house Prometheus text-exposition backend (0.0.4) at
        // `/metrics`, a swift-log structured access log, `/healthz` + `/readyz`, and a
        // swift-distributed-tracing span per request. ISOLATED: it depends on HTTPServer one-way, so its
        // dependencies never enter a core consumer's resolved graph — the bridge stays opt-in.
        .target(
            name: "HTTPObservability",
            dependencies: [
                "HTTPServer",
                .product(name: "Logging", package: "swift-log"),
                .product(name: "Metrics", package: "swift-metrics"),
                .product(name: "Tracing", package: "swift-distributed-tracing"),
                .product(name: "Instrumentation", package: "swift-distributed-tracing"),
                .product(name: "ServiceContextModule", package: "swift-service-context")
            ],
            path: "Sources/HTTPObservability"
        ),
        .testTarget(
            name: "HTTPObservabilityTests",
            dependencies: [
                "HTTPObservability", "HTTPServer", "HTTPCore", "HTTPTestSupport",
                .product(name: "Metrics", package: "swift-metrics"),
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
                "HTTPAuth", "HTTPServer", "HTTPCore", "HTTPTestSupport",
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

let nonSwiftTargets: Set<String> = [
    "CHTTPTestMalloc", "CCRC32", "CEpoll", "CZlibCoding", "CZstd", "CBrotli"
]

for target in package.targets where !nonSwiftTargets.contains(target.name) {
    var settings = (target.swiftSettings ?? []) + strictSwiftSettings
    // SE-0458, staged per `strictMemorySafeTargets` above.
    if strictMemorySafeTargets.contains(target.name) {
        settings.append(.strictMemorySafety())
    }
    if treatWarningsAsErrors {
        settings.append(.treatAllWarnings(as: .error))
    }
    target.swiftSettings = settings
}

// G0 / ADR 0004 — the opt-in portable TLS backbone. Still an ENV-VAR gate (`HTTP_PORTABLE_TLS`),
// deliberately NOT an SE-0450 trait like `Zstd`/`Brotli`: the 2026-08-17 probe of the pinned Swift 6.4
// toolchain established that a trait can only *condition* settings and dependency edges on targets that
// are always declared — it cannot un-declare a root-package target, and the manifest cannot observe
// traits (no `#if`, no Context API). The codings dodge that shortfall because their shims are 2 files
// we own, compiled to empty translation units when the trait is off; `CHTTPBoringSSL` is a 399-file
// vendored C/C++/asm tree, and running all 399 through the compiler on every default build just to
// produce empty objects is exactly the cost this gate exists to avoid. The gate is BoringSSL-shaped and
// expires with BoringSSL: when the vendored tree is deleted (planned Phase 3e), the replacement
// pure-Swift TLS target is ordinary reuse-safe Swift and needs no gate — env var or trait — at all.
//
// Until then: gated by `HTTP_PORTABLE_TLS` so the DEFAULT build graph stays apple/swiftlang-only.
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
