// swift-tools-version: 6.4

// swiftlint:disable file_length - one manifest per package is a SwiftPM invariant: its 30+ targets
import Foundation
import PackageDescription

// MARK: - Strict, *reusable-safe* build settings
let strictSwiftSettings: [SwiftSetting] = [
    .swiftLanguageMode(.v6),
    .enableUpcomingFeature("ExistentialAny"),
    .enableUpcomingFeature("InternalImportsByDefault"),
    .enableUpcomingFeature("MemberImportVisibility"),
    .enableExperimentalFeature("Lifetimes")
]

let strictMemorySafeTargets: Set<String> = [
    "AemiHTTP",
    "HTTPCore",
    "HTTPConcurrency",
    "HTTPTestSupport",
    "HPACK",
    "QPACK",
    "HTTP1",
    "HTTP2",
    "HTTP3",
    "WebSocket",
    "HTTPServer",
    "HTTPTransport",
    "httpd-example",
    "HTTPObservability",
    "HTTPAuth",
    "HTTPDeflate",
    "HTTPZstd",
    "HTTPTLS",
    "HTTPTLSRSA"
]

#if os(Linux)
    let darwinOnlyTransportSources = [
        "Network",
        "POSIXKqueue",
        "SwiftSystem",
        "POSIXDispatch/POSIXDispatchConnection.swift",
        "POSIXDispatch/POSIXDispatchTransport.swift",
        "Quic/LegacyQUICConnection.swift",
        "Quic/LegacyQUICStream.swift",
        "Quic/LegacyQUICTransport.swift",
        "Quic/ModernQUICConnection.swift",
        "Quic/ModernQUICStream.swift",
        "Quic/ModernQUICTransport.swift",
        "Quic/QUICPeer+Network.swift",
        "Quic/QUICTransportFactory.swift"
    ]
    let appleCompressionSources = [
        "Middleware/Brotli.swift",
        "Middleware/Gzip.swift",
        "Middleware/Inflate.swift"
    ]
    let darwinOnlyTransportTestSources = [
        "AcceptShutdownRaceTests.swift",
        "BackboneConformanceTests.swift",
        "CertificateReloadTests.swift",
        "LegacyQUICTransportTests.swift",
        "LoopbackSupport.swift",
        "ModernQUICTransportTests.swift",
        "NetworkFrameworkMutualTLSTests.swift",
        "NetworkFrameworkTLSTests.swift",
        "QUICApplicationCloseProbe.swift",
        "QUICPeerAttributionTests.swift",
        "POSIXSocketTests.swift",
        "ReadinessWaiterCollisionTests.swift"
    ]
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

#if os(macOS)
    let brotliPrefix: String? =
        Context.environment["HTTP_BROTLI_PREFIX"] ?? "/opt/homebrew/opt/brotli"
#else
    let brotliPrefix: String? = Context.environment["HTTP_BROTLI_PREFIX"]
#endif

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

func aemiDependency() -> Package.Dependency {
    if let local = ProcessInfo.processInfo.environment["AEMI_LOCAL_PATH"], !local.isEmpty {
        return .package(path: local)
    }
    return .package(
        url: "https://github.com/Aemi-Studio/aemi.git",
        revision: "9f8d1a3eafed0ad23919b9c68d33606632ce0659"
    )
}

let package = Package(
    name: "HTTP",
    platforms: [
        .macOS("15.6"),
        .iOS(.v18)
    ],
    products: [
        .library(name: "AemiHTTP", targets: ["AemiHTTP"]),
        .library(name: "HTTPCore", targets: ["HTTPCore"]),
        .library(name: "HTTPConcurrency", targets: ["HTTPConcurrency"]),
        .library(name: "HTTPDeflate", targets: ["HTTPDeflate"]),
        .library(name: "HTTPZstd", targets: ["HTTPZstd"]),
        .library(name: "HTTP1", targets: ["HTTP1"]),
        .library(name: "HPACK", targets: ["HPACK"]),
        .library(name: "QPACK", targets: ["QPACK"]),
        .library(name: "HTTP2", targets: ["HTTP2"]),
        .library(name: "HTTP3", targets: ["HTTP3"]),
        .library(name: "WebSocket", targets: ["WebSocket"]),
        .library(name: "HTTPTLS", targets: ["HTTPTLS"]),
        .library(name: "HTTPTLSRSA", targets: ["HTTPTLSRSA"]),
        .library(name: "HTTPTransport", targets: ["HTTPTransport"]),
        .library(name: "HTTPServer", targets: ["HTTPServer"]),
        .library(name: "HTTPObservability", targets: ["HTTPObservability"]),
        .library(name: "HTTPAuth", targets: ["HTTPAuth"]),
        .executable(name: "httpd-example", targets: ["httpd-example"])
    ],
    traits: [
        .trait(name: "Brotli", description: "The RFC 7932 br coding over libbrotli (non-Apple).")
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-system.git", from: "1.8.1"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.16.2"),
        .package(url: "https://github.com/apple/swift-metrics.git", from: "2.12.0"),
        .package(url: "https://github.com/apple/swift-distributed-tracing.git", from: "1.7.2"),
        .package(url: "https://github.com/apple/swift-service-context.git", from: "1.5.1"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "5.1.2"),
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.21.0"),
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.7.3"),
        aemiDependency()
    ],
    targets: [
        .target(
            name: "HTTPCore",
            dependencies: [
                .product(name: "AemiKernels", package: "aemi"),
                .product(name: "AemiKernel", package: "aemi")
            ],
            path: "Sources/Core/HTTPCore"
        ),
        .testTarget(
            name: "HTTPCoreTests",
            dependencies: ["HTTPCore", "HTTPTestSupport"],
            path: "Tests/Core/HTTPCoreTests"
        ),
        .target(name: "HTTPDeflate", dependencies: ["HTTPCore"], path: "Sources/Core/HTTPDeflate"),
        .testTarget(
            name: "HTTPDeflateTests",
            dependencies: ["HTTPDeflate", "HTTPCore", "HTTPTestSupport"],
            path: "Tests/Core/HTTPDeflateTests"
        ),
        .target(
            name: "HTTPConcurrency",
            dependencies: [
                .product(name: "AemiRuntime", package: "aemi")
            ],
            path: "Sources/Core/HTTPConcurrency"
        ),
        .testTarget(
            name: "HTTPConcurrencyTests",
            dependencies: ["HTTPConcurrency", "HTTPTestSupport"],
            path: "Tests/Core/HTTPConcurrencyTests"
        ),
        // The vendored libzstd (scripts/vendor-zstd.sh): `chttpzstd.c` compiles `vendor/zstd.c` with its symbols
        // hidden, so the directory itself is excluded from the target's sources.
        .target(name: "CHTTPZstd", path: "Sources/Core/CHTTPZstd", exclude: ["vendor"]),
        .target(name: "HTTPZstd", dependencies: ["CHTTPZstd"], path: "Sources/Core/HTTPZstd"),
        .testTarget(
            name: "HTTPZstdTests",
            dependencies: ["HTTPZstd"],
            path: "Tests/Core/HTTPZstdTests"
        ),
        codingShim(
            name: "CBrotli",
            path: "Sources/Core/CBrotli",
            trait: "Brotli",
            define: "HTTP_TRAIT_BROTLI",
            libraries: ["brotlienc", "brotlidec", "brotlicommon"],
            prefix: brotliPrefix
        ),
        .target(
            name: "HTTPTestSupport",
            dependencies: [
                "HTTPCore",
                "HTTPConcurrency",
                "HTTPTransport",
                .product(name: "AemiTestKit", package: "aemi")
            ],
            path: "Sources/Testing/HTTPTestSupport"
        ),
        .testTarget(
            name: "HTTPTestSupportTests",
            dependencies: ["HTTPTestSupport"],
            path: "Tests/Testing/HTTPTestSupportTests"
        ),
        .target(
            name: "HTTP1",
            dependencies: [
                "HTTPCore",
                .product(name: "AemiKernel", package: "aemi"),
                .product(name: "AemiKernels", package: "aemi")
            ],
            path: "Sources/Protocols/HTTP1"
        ),
        .testTarget(
            name: "HTTP1Tests",
            dependencies: ["HTTP1", "HTTPTestSupport"],
            path: "Tests/Protocols/HTTP1Tests"
        ),
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
        .target(
            name: "HTTP2",
            dependencies: [
                "HTTPCore",
                "HPACK",
                "HTTPConcurrency",
                .product(name: "AemiKernel", package: "aemi")
            ],
            path: "Sources/Protocols/HTTP2"
        ),
        .testTarget(
            name: "HTTP2Tests",
            dependencies: ["HTTP2", "HPACK", "HTTPTestSupport"],
            path: "Tests/Protocols/HTTP2Tests"
        ),
        .target(
            name: "HTTP3",
            dependencies: ["HTTPCore", "QPACK", "HTTPConcurrency"],
            path: "Sources/Protocols/HTTP3"
        ),
        .testTarget(
            name: "HTTP3Tests",
            dependencies: ["HTTP3", "QPACK", "HTTPCore", "HTTPTestSupport"],
            path: "Tests/Protocols/HTTP3Tests"
        ),
        .target(
            name: "WebSocket",
            dependencies: [
                "HTTPCore", "HTTPDeflate", .product(name: "AemiKernels", package: "aemi")
            ],
            path: "Sources/Protocols/WebSocket"
        ),
        .testTarget(
            name: "WebSocketTests",
            dependencies: ["WebSocket", "HTTPTestSupport"],
            path: "Tests/Protocols/WebSocketTests"
        ),
        .target(
            name: "HTTPTLS",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1")
            ],
            path: "Sources/Protocols/HTTPTLS"
        ),
        .target(
            name: "HTTPTLSRSA",
            dependencies: [
                "HTTPTLS",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto")
            ],
            path: "Sources/Protocols/HTTPTLSRSA"
        ),
        .testTarget(
            name: "HTTPTLSTests",
            dependencies: [
                "HTTPTLS", "HTTPTLSRSA", "HTTPTestSupport", "HTTPTransport",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1")
            ],
            path: "Tests/Protocols/HTTPTLSTests"
        ),
        .target(name: "CEpoll", path: "Sources/Transport/CEpoll"),
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
        .target(
            name: "HTTPServer",
            dependencies: [
                "HTTPCore", "HTTP1", "HTTP2", "HTTP3", "WebSocket", "HTTPTransport",
                "HTTPConcurrency",
                .product(name: "AemiKernel", package: "aemi"),
                .product(name: "Crypto", package: "swift-crypto"),
                "HTTPDeflate",
                "HTTPZstd",
                .target(name: "CBrotli", condition: .when(traits: ["Brotli"]))
            ],
            path: "Sources/Server/HTTPServer",
            exclude: appleCompressionSources
        ),
        .testTarget(
            name: "HTTPServerTests",
            dependencies: [
                "HTTPServer", "HTTP1", "HTTP2", "HTTP3", "HPACK", "QPACK", "WebSocket",
                "HTTPTransport", "HTTPTestSupport", "HTTPDeflate", "HTTPZstd",
                .target(name: "CBrotli", condition: .when(traits: ["Brotli"]))
            ],
            path: "Tests/Server/HTTPServerTests",
            exclude: serverTestExclusions
        ),
        .target(
            name: "AemiHTTP",
            dependencies: [
                "HTTPCore",
                "HTTPConcurrency",
                "HTTP1",
                "HTTP2",
                "HTTP3",
                "WebSocket",
                "HTTPTransport",
                "HTTPServer"
            ],
            path: "Sources/AemiHTTP"
        ),
        .executableTarget(
            name: "httpd-example",
            dependencies: ["HTTPCore", "HTTPServer", "HTTPTransport", "WebSocket"],
            path: "Sources/Examples/httpd-example"
        ),
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
    cxxLanguageStandard: .cxx17
)

let treatWarningsAsErrors = Context.environment["HTTP_WARNINGS_AS_ERRORS"] != nil

let nonSwiftTargets: Set<String> = [
    "CEpoll", "CHTTPZstd", "CBrotli"
]

for target in package.targets where !nonSwiftTargets.contains(target.name) {
    var settings = (target.swiftSettings ?? []) + strictSwiftSettings
    if strictMemorySafeTargets.contains(target.name) {
        settings.append(.strictMemorySafety())
    }
    if treatWarningsAsErrors {
        settings.append(.treatAllWarnings(as: .error))
    }
    target.swiftSettings = settings
}

let httpTLSPortableEngine = Context.environment["HTTP_PORTABLE_TLS"] != nil
let boringSSLPortableEngine = Context.environment["HTTP_BORINGSSL_TLS"] != nil

if httpTLSPortableEngine, boringSSLPortableEngine {
    fatalError(
        "HTTP_PORTABLE_TLS (HTTPTLS engine) and HTTP_BORINGSSL_TLS (legacy A/B engine) are "
            + "mutually exclusive - set exactly one."
    )
}
if httpTLSPortableEngine {
    for target in package.targets where target.name == "HTTPTransport" {
        target.dependencies.append("HTTPTLSRSA")
        target.dependencies.append(.product(name: "Crypto", package: "swift-crypto"))
    }
    for target in package.targets
    where ["HTTPTransport", "HTTPTransportTests"].contains(target.name) {
        target.swiftSettings =
            (target.swiftSettings ?? []) + [.define("HTTP_PORTABLE_TLS_SWIFT")]
        target.dependencies.append("HTTPTLS")
    }
}
if httpTLSPortableEngine || boringSSLPortableEngine {
    package.dependencies.append(.package(path: "Vendor/CHTTPBoringSSL"))
    let boringSSLConsumers =
        boringSSLPortableEngine
        ? ["HTTPTransport", "HTTPTransportTests"] : ["HTTPTransportTests"]
    for target in package.targets where boringSSLConsumers.contains(target.name) {
        target.dependencies.append(
            .product(name: "CHTTPBoringSSL", package: "CHTTPBoringSSL")
        )
        target.dependencies.append(
            .product(name: "CHTTPBoringSSLShims", package: "CHTTPBoringSSL")
        )
    }
}
