//
//  CompressionMiddleware.swift
//  HTTPServer
//
//  Content coding (RFC 9110 §8.4.1 / §12.5.3): when the client offers `gzip` in `Accept-Encoding` and
//  the response is worth compressing, the body is gzip-encoded, `Content-Encoding`/`Content-Length`
//  are updated, and `Vary: Accept-Encoding` is set so caches key on it. The body-transform shape of
//  ``HTTPMiddleware``.
//

internal import Foundation
public import HTTPCore

/// Gzip-compresses eligible responses when the client accepts it (RFC 9110 §8.4.1).
public struct CompressionMiddleware: HTTPMiddleware {

    private let minimumSize: Int

    /// Media-type fragments whose payloads are already compressed — gzip would only add overhead.
    private static let incompressible = [
        "image/", "video/", "audio/", "zip", "gzip", "brotli", "compress",
    ]

    /// Creates the middleware; responses below `minimumSize` octets are not compressed (default 1 KiB,
    /// since tiny bodies cost more in framing overhead than they save).
    public init(minimumSize: Int = 1024) {
        self.minimumSize = minimumSize
    }

    /// Delegates, then gzip-encodes the response body when the client accepts gzip and it is eligible.
    public func respond(
        to request: HTTPRequest,
        body: [UInt8],
        next: any HTTPResponder
    ) async -> ServerResponse {
        var response = await next.respond(to: request, body: body)
        guard acceptsGzip(request) else { return response }
        // The representation now depends on Accept-Encoding (RFC 9110 §12.5.5), even if we skip below.
        addVary(&response)
        guard isEligible(response), let gzipped = Gzip.compress(response.body),
            gzipped.count < response.body.count
        else {
            return response
        }
        response.body = gzipped
        _ = response.head.headerFields.setValue("gzip", for: .contentEncoding)
        _ = response.head.headerFields.setValue(String(gzipped.count), for: .contentLength)
        return response
    }

    /// Whether `request` offers `gzip` (or `*`) with a non-zero quality (RFC 9110 §12.5.3).
    private func acceptsGzip(_ request: HTTPRequest) -> Bool {
        for value in request.headerFields.values(for: .acceptEncoding) {
            for element in value.split(separator: ",") {
                let parts = element.split(separator: ";")
                let coding = parts.first?.trimmingCharacters(in: .whitespaces).lowercased() ?? ""
                guard coding == "gzip" || coding == "*" else { continue }
                if quality(parts.dropFirst()) > 0 { return true }
            }
        }
        return false
    }

    /// The `q=` value among `parameters`, defaulting to 1.0 when absent (RFC 9110 §12.4.2).
    private func quality(_ parameters: ArraySlice<Substring>) -> Double {
        for parameter in parameters {
            let token = parameter.trimmingCharacters(in: .whitespaces).lowercased()
            if token.hasPrefix("q="), let value = Double(token.dropFirst(2)) { return value }
        }
        return 1.0
    }

    /// Whether `response` is worth compressing: large enough, not already encoded, not already-compressed media.
    private func isEligible(_ response: ServerResponse) -> Bool {
        guard response.body.count >= minimumSize else { return false }
        guard !response.head.headerFields.contains(.contentEncoding) else { return false }
        guard let type = response.head.headerFields[.contentType]?.lowercased() else { return true }
        return !Self.incompressible.contains { type.contains($0) }
    }

    private func addVary(_ response: inout ServerResponse) {
        let alreadyVaries = response.head.headerFields.values(for: .vary)
            .contains { $0.lowercased().contains("accept-encoding") }
        guard !alreadyVaries else { return }
        _ = response.head.headerFields.append("Accept-Encoding", for: .vary)
    }
}
