// swift-tools-version: 6.0
//
//  Package.swift — vapor-bench
//
//  The Vapor baseline for the Bench/ comparison: a minimal Vapor server implementing the shared parity
//  route set. Deliberately its OWN package (like hb-bench) so Vapor and the SwiftNIO stack never enter
//  the HTTP library's consumer-facing dependency graph — they exist only here, as a yardstick.
//

import PackageDescription

let package = Package(
    name: "vapor-bench",
    platforms: [.macOS(.v14)],
    dependencies: [
        .package(url: "https://github.com/vapor/vapor.git", from: "4.100.0")
    ],
    targets: [
        .executableTarget(
            name: "vapor-bench",
            dependencies: [.product(name: "Vapor", package: "vapor")]
        )
    ]
)
