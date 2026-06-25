// swift-tools-version: 6.0
//
//  Package.swift — hb-bench
//
//  The in-language SwiftNIO baseline for the Bench/ comparison: a minimal Hummingbird server that
//  mirrors httpd-example's routes. Deliberately its OWN package (like Benchmarks/) so SwiftNIO and the
//  Hummingbird stack never enter the HTTP library's consumer-facing dependency graph — they exist only
//  here, as a yardstick to answer "are we competitive without NIO?" on an identical workload.
//

import PackageDescription

let package = Package(
    name: "hb-bench",
    platforms: [.macOS(.v14)],  // Hummingbird 2.x floor
    dependencies: [
        .package(url: "https://github.com/hummingbird-project/hummingbird.git", from: "2.0.0")
    ],
    targets: [
        .executableTarget(
            name: "hb-bench",
            dependencies: [.product(name: "Hummingbird", package: "hummingbird")]
        )
    ]
)
