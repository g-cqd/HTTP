//
//  DateHeaderMiddleware.swift
//  HTTPServer
//
//  Stamps the `Date` response header (RFC 9110 §6.6.1) in IMF-fixdate form. The clock is injected as a
//  Unix-timestamp provider, so the default uses wall-clock time while tests pin it deterministically.
//

internal import Foundation
public import HTTPCore

/// Adds a `Date` header (RFC 9110 §6.6.1) to responses that lack one.
public struct DateHeaderMiddleware: HTTPMiddleware {
    private let now: @Sendable () -> Int
    /// Formats the `Date` string once per whole-second tick (a shared, `Mutex`-guarded cache), so the
    /// 200k-rps hot path reuses one string per second instead of rebuilding it on every response.
    private let cache = DateCache()

    /// Creates the middleware reading the system wall clock.
    public init() {
        self.now = { Int(Date().timeIntervalSince1970) }
    }

    /// Creates the middleware with an injected clock — `now` returns seconds since the Unix epoch.
    public init(now: @escaping @Sendable () -> Int) {
        self.now = now
    }

    /// Delegates, then stamps `Date` if the responder did not set it.
    public func respond(
        to request: HTTPRequest,
        body: [UInt8],
        next: any HTTPResponder
    ) async -> ServerResponse {
        var response = await next.respond(to: request, body: body)
        if !response.head.headerFields.contains(.date) {
            _ = response.head.headerFields.append(cache.formatted(for: now()), for: .date)
        }
        return response
    }
}
