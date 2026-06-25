//
//  RangeMiddleware.swift
//  HTTPServer
//
//  Range requests (RFC 9110 §14). For a successful GET carrying a single `bytes=` range, the
//  middleware slices the response body and returns `206 Partial Content` with `Content-Range` and a
//  trimmed body; a well-formed range past the body becomes `416 Range Not Satisfiable` with
//  `Content-Range: bytes */<total>`. Every range-able 200 GET advertises `Accept-Ranges: bytes`.
//  Multi-range and `If-Range` are out of scope for v1: §14.2 lets a server ignore `Range`, so a
//  multi-range, non-`bytes`, or unparseable request falls back to the full 200 — fail-open to a
//  correct full representation, never a malformed partial.
//

public import HTTPCore

/// Serves a single-range `Range: bytes=…` request as `206 Partial Content` (RFC 9110 §14).
public struct RangeMiddleware: HTTPMiddleware {
    /// Creates the middleware.
    public init() {
        // Stateless; nothing to configure.
    }

    /// Delegates, advertises `Accept-Ranges` on a range-able response, and serves `206`/`416` when the
    /// request asks for a satisfiable / unsatisfiable single byte range.
    public func respond(
        to request: HTTPRequest,
        body: [UInt8],
        next: any HTTPResponder
    ) async -> ServerResponse {
        var response = await next.respond(to: request, body: body)
        // Only a successful, bodied GET is range-able (a partial of an error or empty body is
        // meaningless; HEAD shares GET's header section but carries no body to slice).
        guard request.method == .get, response.head.status == .ok, !response.body.isEmpty else {
            return response
        }
        _ = response.head.headerFields.setValue("bytes", for: .acceptRanges)
        guard let header = request.headerFields[.range] else {
            return response  // a normal 200 that now advertises range support
        }
        let total = response.body.count
        switch Self.parse(header, total: total) {
            case .ignore:
                return response  // ignored Range (§14.2) — serve the full 200
            case .unsatisfiable:
                var rejected = HTTPResponse(status: .rangeNotSatisfiable)
                _ = rejected.headerFields.setValue("bytes */\(total)", for: .contentRange)
                _ = rejected.headerFields.setValue("bytes", for: .acceptRanges)
                return ServerResponse(rejected)
            case .satisfiable(let start, let end):
                response.head.status = .partialContent
                _ = response.head.headerFields.setValue(
                    "bytes \(start)-\(end)/\(total)", for: .contentRange
                )
                response.body = Array(response.body[start ... end])
                return response
        }
    }

    /// The outcome of parsing a `Range` header value against a body of `total` octets.
    enum ParsedRange: Equatable, Sendable {
        /// An inclusive `[start, end]` byte range within the body.
        case satisfiable(start: Int, end: Int)
        /// A well-formed range entirely past the body — answered with `416` (RFC 9110 §15.5.17).
        case unsatisfiable
        /// Unparseable, multi-range, or a non-`bytes` unit — the `Range` is ignored (serve the 200).
        case ignore
    }

    /// Parses a single `bytes=` byte-range against `total` (RFC 9110 §14.1.2).
    ///
    /// Fail-open: anything but a single, well-formed `bytes` range returns ``ParsedRange/ignore``
    /// (serve the full body).
    static func parse(_ value: String, total: Int) -> ParsedRange {
        guard total > 0, value.hasPrefix("bytes=") else {
            return .ignore
        }
        let spec = value.dropFirst("bytes=".count)
        guard !spec.contains(","), let dash = spec.firstIndex(of: "-") else {
            return .ignore  // multi-range (comma) or no hyphen → ignore
        }
        let firstText = spec[..<dash]
        let lastText = spec[spec.index(after: dash)...]
        if firstText.isEmpty {
            // Suffix form `bytes=-N`: the last N octets, clamped to the whole body.
            guard let suffix = Int(lastText), suffix > 0 else {
                return .ignore
            }
            return .satisfiable(start: max(0, total - suffix), end: total - 1)
        }
        guard let first = Int(firstText), first >= 0 else {
            return .ignore
        }
        if lastText.isEmpty {
            return first < total ? .satisfiable(start: first, end: total - 1) : .unsatisfiable
        }
        guard let last = Int(lastText), last >= first else {
            return .ignore  // last < first is an invalid range-spec → ignore (§14.1.2)
        }
        return first < total
            ? .satisfiable(start: first, end: min(last, total - 1))
            : .unsatisfiable
    }
}
