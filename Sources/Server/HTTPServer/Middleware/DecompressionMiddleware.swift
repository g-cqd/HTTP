//
//  DecompressionMiddleware.swift
//  HTTPServer
//
//  RFC 9110 §8.4 — optional inbound Content-Encoding decompression (gzip, deflate, and Brotli). OFF by
//  default: it is net-new attack surface, so a server opts in only when it actually consumes coded
//  request bodies. Bomb-hardened (CWE-409): the decompressed size is capped both absolutely
//  (HTTPLimits.maxDecompressedBodySize) and by ratio (maxDecompressionRatio) against the octets the
//  peer actually sent, the coding list depth is capped (maxDecompressionLayers), and a malformed,
//  oversized, or over-ratio body fails closed with 413 Content Too Large rather than buffering a bomb.
//
//  The `Content-Encoding` field is read *before* the body is touched. Reading it afterwards meant
//  merely installing this middleware converted every streamed request in the server into a buffered
//  one — a global regression bought by adding one line to a chain.
//

public import HTTPCore

/// Decompresses a coded request body before the responder, bounded against bombs (RFC 9110 §8.4).
///
/// Opt-in: it does nothing unless added to the chain. It handles `gzip`, `deflate`, and `br`. A body
/// whose outermost coding it does not decode — including one with no `Content-Encoding` at all — is
/// forwarded **untouched**, streaming intact. A coded body that is malformed, exceeds the absolute
/// cap, or exceeds the ratio cap is rejected with `413 Content Too Large` (CWE-409 decompression-bomb
/// defense); a coding list that is malformed or deeper than the configured depth is rejected with
/// `415 Unsupported Media Type` (RFC 9110 §15.5.16).
///
/// This middleware bounds *its own* output, which is the only thing that can: a wire-body limit such
/// as ``BodyLimitMiddleware`` measured the coded octets and says nothing about what a decoder expands
/// them into.
public struct DecompressionMiddleware: HTTPMiddleware {
    /// The content codings this middleware decodes; any other is passed through untouched. `br` needs a
    /// Brotli decoder — Apple's Compression on Darwin, the opt-in libbrotli shim on Linux — so it is only
    /// claimed where one is present (else a `br` body passes through, rather than being wrongly rejected).
    #if canImport(Compression) || canImport(CBrotli)
        private static let supported: Set<String> = ["gzip", "x-gzip", "deflate", "br"]
    #elseif canImport(CZlibCoding)
        private static let supported: Set<String> = ["gzip", "x-gzip", "deflate"]
    #else
        private static let supported: Set<String> = []
    #endif

    private let maxDecompressedSize: Int
    private let maxRatio: Int
    private let maxCodings: Int

    /// Creates the middleware with the decompressed-size, ratio, and coding-depth caps (defaulting to
    /// ``HTTPLimits``), or **nil** when any of them is not a bound.
    ///
    /// Rejected at initialization rather than clamped, because a decompression middleware whose bound
    /// is not a bound is the vulnerability it exists to prevent, and silently substituting a different
    /// limit would hide that from the operator who configured it:
    ///
    /// - `maxDecompressedSize` must be in `1 ..< Int.max`. Zero admits nothing (do not install the
    ///   middleware instead), and `Int.max` is the *absence* of a cap, not a large one.
    /// - `maxRatio` must be in `1 ..< Int.max`, for the same reasons.
    /// - `maxCodings` must be at least one.
    public init?(
        maxDecompressedSize: Int = HTTPLimits.default.maxDecompressedBodySize,
        maxRatio: Int = HTTPLimits.default.maxDecompressionRatio,
        maxCodings: Int = HTTPLimits.default.maxDecompressionLayers
    ) {
        guard maxDecompressedSize > 0, maxDecompressedSize < .max,
            maxRatio > 0, maxRatio < .max,
            maxCodings > 0
        else {
            return nil
        }
        self.maxDecompressedSize = maxDecompressedSize
        self.maxRatio = maxRatio
        self.maxCodings = maxCodings
    }

    /// Decompresses a coded body under the caps, rewrites `Content-Encoding` to whatever remains, and
    /// passes the decoded body on; forwards a body it will not decode untouched.
    public func respond(
        to request: HTTPRequest,
        body: RequestBody,
        context: RequestContext,
        next: any HTTPResponder
    ) async -> ServerResponse {
        // The header first, always: a request this middleware will not decode must reach the
        // responder exactly as it arrived, streaming and all.
        guard let field = request.headerFields[.contentEncoding] else {
            return await next.respond(to: request, body: body, context: context)
        }
        guard let list = ContentCodingList(field, limit: maxCodings) else {
            return ServerResponse(HTTPResponse(status: .unsupportedMediaType))
        }
        guard let outermost = list.codings.last, Self.supported.contains(outermost) else {
            return await next.respond(to: request, body: body, context: context)
        }
        return await decode(request, list: list, body: body, context: context, next: next)
    }

    /// Buffers the coded body under the absolute cap, peels the codings, and forwards the result.
    private func decode(
        _ request: HTTPRequest,
        list: ContentCodingList,
        body: RequestBody,
        context: RequestContext,
        next: any HTTPResponder
    ) async -> ServerResponse {
        // The coded body is bounded by the decompressed cap: no decoder that is worth applying
        // expands a body, so coded octets beyond the largest output we would accept cannot produce an
        // acceptable result. Buffering is unavoidable here — a coding is only meaningful whole.
        guard
            let coded = await body.collect(
                maximum: maxDecompressedSize,
                expecting: Self.declaredLength(of: request)
            )
        else {
            return ServerResponse(HTTPResponse(status: .contentTooLarge))
        }
        guard !coded.isEmpty else {
            return await next.respond(to: request, body: .collected(coded), context: context)
        }
        #if canImport(Compression) || canImport(CZlibCoding)
            guard let peeled = peel(coded, list: list) else {
                return ServerResponse(HTTPResponse(status: .contentTooLarge))
            }
            return await next.respond(
                to: Self.rewriting(request, to: peeled),
                body: .collected(peeled.bytes),
                context: context
            )
        #else
            // No inbound decoder in this build; `supported` is empty, so this is unreachable — the
            // body is forwarded exactly as an unrecognized coding would be.
            return await next.respond(to: request, body: .collected(coded), context: context)
        #endif
    }

    #if canImport(Compression) || canImport(CZlibCoding)
        /// Undoes the codings from the right until one is not ours, or nil if any layer breaches a cap.
        ///
        /// RFC 9110 §8.4.1 lists codings in the order they were applied, so the last is the outermost.
        /// The cap is computed **once, from the octets the peer actually sent**, and applies to every
        /// layer: stacking codings therefore cannot buy more amplification than a single one, which is
        /// the property a per-layer ratio would have lost (CWE-409).
        private func peel(
            _ coded: [UInt8],
            list: ContentCodingList
        ) -> (bytes: [UInt8], remaining: ArraySlice<String>)? {
            let product = coded.count.multipliedReportingOverflow(by: maxRatio)
            let cap = min(maxDecompressedSize, product.overflow ? Int.max : product.partialValue)
            var bytes = coded
            var remaining = list.codings[...]
            while let coding = remaining.last, Self.supported.contains(coding) {
                guard let decoded = Inflate.decompress(bytes, encoding: coding, maxOutput: cap)
                else {
                    return nil
                }
                bytes = decoded
                remaining = remaining.dropLast()
            }
            return (bytes, remaining)
        }
    #endif

    /// `request` with `Content-Encoding` reduced to the codings still applied (removed when none are)
    /// and `Content-Length` restated for the decoded body.
    private static func rewriting(
        _ request: HTTPRequest,
        to peeled: (bytes: [UInt8], remaining: ArraySlice<String>)
    ) -> HTTPRequest {
        var rewritten = request
        if peeled.remaining.isEmpty {
            rewritten.headerFields.removeAll(named: .contentEncoding)  // the body is now identity
        }
        else {
            _ = rewritten.headerFields.setValue(
                peeled.remaining.joined(separator: ", "), for: .contentEncoding
            )
        }
        _ = rewritten.headerFields.setValue(String(peeled.bytes.count), for: .contentLength)
        return rewritten
    }

    /// The declared `Content-Length`, when the request states a usable one — a reservation hint only,
    /// which ``RequestBody/collect(maximum:expecting:)`` bounds before trusting.
    private static func declaredLength(of request: HTTPRequest) -> Int? {
        guard let value = request.headerFields[.contentLength], let length = Int(value), length > 0
        else {
            return nil
        }
        return length
    }
}
