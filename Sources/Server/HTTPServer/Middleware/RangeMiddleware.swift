//
//  RangeMiddleware.swift
//  HTTPServer
//
//  Range requests (RFC 9110 §14). For a range-able 200 GET the middleware serves a single `bytes=`
//  range as `206 Partial Content` (Content-Range + sliced body), several ranges as a
//  `206 multipart/byteranges` envelope (§14.6), and a range entirely past the body as `416`. `If-Range`
//  (§13.1.5) serves the range only when the client's validator still matches — otherwise the full 200.
//  A multi-range request is capped (CVE-2011-3192 range-amplification) and otherwise falls open to the
//  full 200; §14.2 lets a server ignore any Range it does not honor.
//

public import HTTPCore

/// Serves `Range: bytes=…` as `206 Partial Content` — single or `multipart/byteranges` (RFC 9110 §14).
public struct RangeMiddleware: HTTPMiddleware {
    /// The most byte-ranges one request may ask for before the Range is ignored — a small cap bounds the
    /// response amplification a flood of overlapping ranges could cause (CVE-2011-3192 / CWE-400).
    private static let maxRanges = 8

    /// Creates the middleware.
    public init() {
        // Stateless; nothing to configure.
    }

    /// Delegates, advertises `Accept-Ranges`, honors `If-Range`, and serves `206`/`416` for a
    /// satisfiable / unsatisfiable byte-range request.
    public func respond(
        to request: HTTPRequest,
        body: [UInt8],
        next: any HTTPResponder
    ) async -> ServerResponse {
        var response = await next.respond(to: request, body: body)
        // Only a successful, bodied GET is range-able (HEAD shares GET's header section but carries no
        // body to slice; a partial of an error or empty body is meaningless).
        guard request.method == .get, response.head.status == .ok, !response.body.isEmpty else {
            return response
        }
        _ = response.head.headerFields.setValue("bytes", for: .acceptRanges)
        guard let header = request.headerFields[.range] else {
            return response  // a normal 200 that now advertises range support
        }
        // If-Range: serve the range only if the client's validator still matches (§13.1.5); otherwise
        // serve the full current representation.
        if let ifRange = request.headerFields[.ifRange], !ifRangeMatches(ifRange, response) {
            return response
        }
        let total = response.body.count
        return Self.isMultiRange(header)
            ? multiRange(header, response, total: total)
            : singleRange(header, response, total: total)
    }

    // MARK: Single range

    private func singleRange(
        _ header: String,
        _ response: ServerResponse,
        total: Int
    ) -> ServerResponse {
        var response = response
        switch Self.parse(header, total: total) {
            case .ignore:
                return response
            case .unsatisfiable:
                return Self.unsatisfiable(total: total)
            case .satisfiable(let start, let end):
                response.head.status = .partialContent
                _ = response.head.headerFields.setValue(
                    "bytes \(start)-\(end)/\(total)", for: .contentRange
                )
                response.body = Array(response.body[start ... end])
                return response
        }
    }

    // MARK: Multi range (multipart/byteranges, §14.6)

    private func multiRange(
        _ header: String,
        _ response: ServerResponse,
        total: Int
    ) -> ServerResponse {
        let specs = header.dropFirst("bytes=".count).split(separator: ",")
        // Too many ranges — fail open to the full 200 (CVE-2011-3192).
        guard specs.count <= Self.maxRanges else {
            return response
        }
        var ranges: [(start: Int, end: Int)] = []
        for spec in specs {
            switch Self.resolve(Self.trimmed(spec), total: total) {
                case .satisfiable(let start, let end):
                    ranges.append((start, end))
                case .unsatisfiable:
                    continue  // drop an unsatisfiable part; keep the satisfiable ones
                case .ignore:
                    // A malformed part voids the whole Range (§14.2) — serve the full 200.
                    return response
            }
        }
        guard !ranges.isEmpty else {
            return Self.unsatisfiable(total: total)  // every part was past the body
        }
        return Self.multipart(ranges, response: response, total: total)
    }

    /// Builds the `206 multipart/byteranges` envelope (RFC 9110 §14.6).
    private static func multipart(
        _ ranges: [(start: Int, end: Int)],
        response: ServerResponse,
        total: Int
    ) -> ServerResponse {
        var response = response
        let boundary = makeBoundary()
        let contentType = response.head.headerFields[.contentType]
        let source = response.body
        var body: [UInt8] = []
        for range in ranges {
            append("--\(boundary)\r\n", to: &body)
            if let contentType {
                append("Content-Type: \(contentType)\r\n", to: &body)
            }
            append("Content-Range: bytes \(range.start)-\(range.end)/\(total)\r\n\r\n", to: &body)
            body.append(contentsOf: source[range.start ... range.end])
            append("\r\n", to: &body)
        }
        append("--\(boundary)--\r\n", to: &body)
        response.head.status = .partialContent
        _ = response.head.headerFields.setValue(
            "multipart/byteranges; boundary=\(boundary)", for: .contentType
        )
        response.body = body
        return response
    }

    // MARK: If-Range (§13.1.5)

    /// Whether the request may have the range — the `If-Range` validator still matches the current
    /// representation (a strong `ETag`, or an exact `Last-Modified`).
    ///
    /// A weak tag is never usable with `If-Range` (RFC 9110 §13.1.5).
    private func ifRangeMatches(_ ifRange: String, _ response: ServerResponse) -> Bool {
        let validator = String(Self.trimmed(ifRange[...]))
        if validator.hasPrefix("\"") || validator.hasPrefix("W/") {
            guard !validator.hasPrefix("W/") else {
                return false
            }
            let etag = response.head.headerFields[.etag] ?? EntityTag.crc(for: response.body)
            return validator == etag
        }
        // An HTTP-date If-Range must exactly equal the representation's Last-Modified.
        let lastModified = response.head.headerFields[.lastModified].flatMap(HTTPDate.parse)
        guard let lastModified, let ifRangeDate = HTTPDate.parse(validator) else {
            return false
        }
        return lastModified == ifRangeDate
    }

    // MARK: Parsing

    /// The outcome of parsing a `Range` header value against a body of `total` octets.
    enum ParsedRange: Equatable, Sendable {
        /// An inclusive `[start, end]` byte range within the body.
        case satisfiable(start: Int, end: Int)
        /// A well-formed range entirely past the body — answered with `416` (RFC 9110 §15.5.17).
        case unsatisfiable
        /// Unparseable, multi-range, or a non-`bytes` unit — the `Range` is ignored (serve the 200).
        case ignore
    }

    /// Parses a single `bytes=` byte-range against `total` (RFC 9110 §14.1.2); a comma list is
    /// ``ParsedRange/ignore`` here — multi-range is handled separately.
    static func parse(_ value: String, total: Int) -> ParsedRange {
        guard total > 0, value.hasPrefix("bytes=") else {
            return .ignore
        }
        let spec = value.dropFirst("bytes=".count)
        guard !spec.contains(",") else {
            return .ignore
        }
        return resolve(spec, total: total)
    }

    /// Resolves one range-spec (`first-last`, `first-`, or `-suffix`) against `total`.
    static func resolve(_ spec: Substring, total: Int) -> ParsedRange {
        guard total > 0, let dash = spec.firstIndex(of: "-") else {
            return .ignore
        }
        let firstText = spec[..<dash]
        let lastText = spec[spec.index(after: dash)...]
        if firstText.isEmpty {
            // Suffix form `-N`: the last N octets, clamped to the whole body.
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

    // MARK: Helpers

    private static func isMultiRange(_ header: String) -> Bool {
        header.hasPrefix("bytes=") && header.dropFirst("bytes=".count).contains(",")
    }

    private static func unsatisfiable(total: Int) -> ServerResponse {
        var rejected = HTTPResponse(status: .rangeNotSatisfiable)
        _ = rejected.headerFields.setValue("bytes */\(total)", for: .contentRange)
        _ = rejected.headerFields.setValue("bytes", for: .acceptRanges)
        return ServerResponse(rejected)
    }

    /// A fresh multipart boundary unlikely to collide with body content (64 random bits).
    private static func makeBoundary() -> String {
        var rng = SystemRandomNumberGenerator()
        return "byteranges-\(String(UInt64.random(in: .min ... .max, using: &rng), radix: 16))"
    }

    private static func append(_ text: String, to body: inout [UInt8]) {
        body.append(contentsOf: text.utf8)
    }

    /// `slice` without leading/trailing spaces or tabs (RFC 9110 OWS).
    private static func trimmed(_ slice: Substring) -> Substring {
        var slice = slice
        while let first = slice.first, first == " " || first == "\t" { slice = slice.dropFirst() }
        while let last = slice.last, last == " " || last == "\t" { slice = slice.dropLast() }
        return slice
    }
}
