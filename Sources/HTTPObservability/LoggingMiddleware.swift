//
//  LoggingMiddleware.swift
//  HTTPObservability
//
//  A structured access log over swift-log: one `info` record per response carrying the method, path,
//  response status, latency, and the `X-Request-ID` correlation id as metadata fields (so a backend can
//  index them rather than scrape a flat line). The chain is timed on the injected monotonic clock. This
//  is distinct from HTTPServer's string-sink `AccessLogMiddleware`; install whichever a deployment wants.
//

public import HTTPCore
public import HTTPServer
public import Logging

/// Logs one structured access entry per response through a swift-log `Logger`.
public struct LoggingMiddleware<C: Clock>: HTTPMiddleware where C.Duration == Duration {
    private let logger: Logger
    private let clock: C
    private let message: Logger.Message

    /// Creates the middleware logging through `logger`, timing the chain against `clock`.
    public init(_ logger: Logger, clock: C, message: Logger.Message = "http_request") {
        self.logger = logger
        self.clock = clock
        self.message = message
    }

    /// Times the delegated response and logs its method, path, status, duration, and request id.
    public func respond(
        to request: HTTPRequest,
        body: [UInt8],
        next: any HTTPResponder
    ) async -> ServerResponse {
        let start = clock.now
        let response = await next.respond(to: request, body: body)
        var metadata: Logger.Metadata = [
            "method": .string(request.method.rawValue),
            "path": .string(Self.pathOnly(request.path)),
            "status": .string(String(response.head.status.code)),
            "duration_ms": .stringConvertible(Self.milliseconds(start.duration(to: clock.now)))
        ]
        if let requestID = request.headerFields[.xRequestID] {
            metadata["request_id"] = .string(requestID)
        }
        logger.info(message, metadata: metadata)
        return response
    }

    /// The request path without its query string.
    ///
    /// Query strings routinely carry tokens/PII and an access log is a common credential sink (audit F5).
    /// Mirrors OTel `url.path` (path only).
    private static func pathOnly(_ target: String) -> String {
        String(target.prefix { $0 != "?" && $0 != "#" })
    }

    /// `duration` as fractional milliseconds (monotonic, so never negative).
    private static func milliseconds(_ duration: Duration) -> Double {
        let components = duration.components
        return Double(components.seconds) * 1_000
            + Double(components.attoseconds) / 1_000_000_000_000_000
    }
}

extension LoggingMiddleware where C == ContinuousClock {
    /// Creates the middleware timing against the real ``ContinuousClock`` (the production default).
    public init(_ logger: Logger, message: Logger.Message = "http_request") {
        self.init(logger, clock: ContinuousClock(), message: message)
    }
}
