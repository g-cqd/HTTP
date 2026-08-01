//
//  BenchmarkProfile.swift
//  httpd-example
//
//  The two-mode axis of the comparative benchmark (`Benchmarking/Bench/run.sh`), selected by the
//  `HTTPD_PROFILE` environment variable.
//
//  WHY THIS EXISTS. Every prior round of the comparative battletest ran this example with its full
//  production middleware chain against peer servers running framework-floor handlers — a bare route
//  closure, no middleware at all. The two are not the same workload, so "N % behind hyper" was a
//  sentence about two different programs. That confound is removed by making the stack a run-time
//  choice and measuring BOTH:
//
//    • `floor` — the router and nothing else. This is the column that is comparable to a peer's
//      framework-floor handler, because it does the same work: parse, route, serialize, write.
//    • `full`  — the chain `HTTPDExample` actually ships (metrics, decompression, compression,
//      Server/Date, security headers, CORS, conditional GET, Range). This is the column that says
//      what you get when you deploy the example as written.
//
//  The DIFFERENCE between the two columns is the deliverable: it is the first measurement in this
//  repository that prices the middleware chain, and it tells a reader which column belongs next to
//  which peer number. Neither column alone is the honest answer.
//
//  `floor` is a benchmark posture, not a recommendation: it serves without `Date` (RFC 9110 §6.6.1
//  requires an origin server with a clock to send one), without the security headers, and without
//  conditional-request handling. It exists to be measured, not deployed.
//

import Foundation
import HTTPServer

/// Which middleware chain the example serves behind — the comparative benchmark's two-mode axis.
///
/// Read from `HTTPD_PROFILE`; anything other than `floor` means the shipped `full` chain, so an
/// unset or misspelled variable can never silently downgrade a real deployment.
enum BenchmarkProfile: String, Sendable, CaseIterable {
    /// Router only — the apples-to-apples column against a peer framework's floor handler.
    case floor

    /// The chain the example ships with — the "what you actually deploy" column.
    case full

    /// The profile named by `HTTPD_PROFILE`, defaulting to ``full``.
    ///
    /// Fail-safe by construction: only the exact string `floor` strips the chain. A typo, an empty
    /// value, or an unset variable all resolve to the shipped stack.
    static var current: Self {
        let raw = ProcessInfo.processInfo.environment["HTTPD_PROFILE"] ?? ""
        return Self(rawValue: raw) ?? .full
    }

    /// The middleware chain for this profile, outermost first.
    ///
    /// `quiet` drops the per-request access-log `print`, which dominates under load and which no
    /// reference server in the comparison performs; it is honored in both profiles so the flag means
    /// the same thing in each.
    func middlewares(metrics: ExampleMetrics, quiet: Bool) -> [any HTTPMiddleware] {
        var middlewares: [any HTTPMiddleware] = []
        if !quiet {
            middlewares.append(AccessLogMiddleware { print("httpd-example: \($0)") })
        }
        guard self == .full else {
            return middlewares
        }
        middlewares.append(MetricsMiddleware(metrics))  // RED signals over the whole chain
        // Inbound: gunzip a gzip body (bomb-capped). The initializer is failable because it refuses a
        // configuration that is not a bound; the shipped defaults are one, so this always succeeds.
        if let decompression = DecompressionMiddleware() {
            middlewares.append(decompression)
        }
        middlewares.append(
            contentsOf: [
                CompressionMiddleware(),  // gzip the outgoing body
                ServerHeaderMiddleware("httpd-example"),
                DateHeaderMiddleware(),
                SecurityHeadersMiddleware(),
                CORSMiddleware(),
                ConditionalRequestMiddleware(),  // ETag on the raw body, If-None-Match → 304
                RangeMiddleware()  // innermost: Range → 206 (§14)
            ] as [any HTTPMiddleware]
        )
        return middlewares
    }
}
