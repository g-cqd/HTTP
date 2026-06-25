//
//  DecompressionMiddleware.swift
//  HTTPServer
//
//  RFC 9110 §8.4 — optional inbound Content-Encoding (gzip) decompression. OFF by default: it is
//  net-new attack surface, so a server opts in only when it actually consumes coded request bodies.
//  Bomb-hardened (CWE-409): the decompressed size is capped both absolutely
//  (HTTPLimits.maxDecompressedBodySize) and by ratio (maxDecompressionRatio), and a malformed,
//  oversized, or over-ratio body fails closed with 413 Content Too Large rather than buffering a bomb.
//

public import HTTPCore

/// Decompresses a gzip-coded request body before the responder, bounded against bombs (RFC 9110 §8.4).
///
/// Opt-in: it does nothing unless added to the chain. A non-gzip (or absent) `Content-Encoding` is left
/// untouched for the responder; a `gzip` body that is malformed, exceeds the absolute cap, or exceeds the
/// ratio cap is rejected with `413 Content Too Large` (CWE-409 decompression-bomb defense).
public struct DecompressionMiddleware: HTTPMiddleware {
    private let maxDecompressedSize: Int
    private let maxRatio: Int

    /// Creates the middleware with the decompressed-size and ratio caps (defaulting to ``HTTPLimits``).
    public init(
        maxDecompressedSize: Int = HTTPLimits.default.maxDecompressedBodySize,
        maxRatio: Int = HTTPLimits.default.maxDecompressionRatio
    ) {
        self.maxDecompressedSize = maxDecompressedSize
        self.maxRatio = maxRatio
    }

    /// Decompresses a gzip-coded body under the caps, strips `Content-Encoding`, and passes the identity
    /// body on; leaves a non-gzip (or absent) `Content-Encoding` untouched.
    public func respond(
        to request: HTTPRequest,
        body: [UInt8],
        next: any HTTPResponder
    ) async -> ServerResponse {
        guard !body.isEmpty, request.headerFields[.contentEncoding]?.lowercased() == "gzip" else {
            return await next.respond(to: request, body: body)
        }
        // Cap the decompressed size both absolutely and by ratio (overflow-safe), then decode under it:
        // a small body must not be allowed to expand without bound (CWE-409).
        let product = body.count.multipliedReportingOverflow(by: maxRatio)
        let cap = min(maxDecompressedSize, product.overflow ? Int.max : product.partialValue)
        guard let inflated = Inflate.gunzip(body, maxOutput: cap) else {
            // A bomb past the cap, an over-ratio body, or a malformed gzip member — fail closed.
            return ServerResponse(HTTPResponse(status: .contentTooLarge))
        }
        var decoded = request
        decoded.headerFields.removeAll(named: .contentEncoding)  // the body is now identity
        _ = decoded.headerFields.setValue(String(inflated.count), for: .contentLength)
        return await next.respond(to: decoded, body: inflated)
    }
}
