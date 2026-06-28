//
//  CompressionMiddleware.swift
//  HTTPServer
//
//  Content coding (RFC 9110 §8.4.1 / §12.5.3): the response body is encoded with the client's most
//  preferred coding that we can produce — Brotli (RFC 7932), zstd (RFC 8878), or gzip (RFC 1952) —
//  selected from `Accept-Encoding` by q-value, with the server preference br > zstd > gzip breaking
//  a tie. `Content-Encoding`/`Content-Length` are updated and `Vary: Accept-Encoding` is set so
//  caches key on it. Brotli uses Darwin's level-2 encoder (the portable/Linux `libbrotlienc` shim
//  is gap G0); zstd is the opt-in `CZstd` shim over the system libzstd (`HTTP_ZSTD`), absent from
//  the default graph and guarded by `#if canImport(CZstd)`. The body-transform shape of
//  ``HTTPMiddleware``.
//

internal import Foundation
public import HTTPCore

/// Compresses eligible responses with the client's preferred content coding — Brotli or gzip
/// (RFC 9110 §8.4.1).
public struct CompressionMiddleware: HTTPMiddleware {
    private let minimumSize: Int

    /// Media-type fragments whose payloads are already compressed — re-encoding only adds overhead.
    private static let incompressible = [
        "image/", "video/", "audio/", "zip", "gzip", "brotli", "zstd", "compress"
    ]

    /// A content coding this middleware can produce, in server-preference order — Brotli, then zstd
    /// (only when the opt-in `CZstd` shim is present), then gzip. `CaseIterable` order is source
    /// order, so this is exactly the br > zstd > gzip tie-break the negotiator applies (§12.5.3).
    private enum Coding: CaseIterable {
        case br
        #if canImport(CZstd)
            case zstd
        #endif
        case gzip

        /// The `Content-Encoding` token (RFC 9110 §8.4.1 / RFC 7932 / RFC 8878 / RFC 1952).
        var token: String {
            switch self {
                case .br:
                    return "br"
                #if canImport(CZstd)
                    case .zstd:
                        return "zstd"
                #endif
                case .gzip:
                    return "gzip"
            }
        }
    }

    /// Creates the middleware; responses below `minimumSize` octets are not compressed (default 1 KiB,
    /// since tiny bodies cost more in framing overhead than they save).
    public init(minimumSize: Int = 1_024) {
        self.minimumSize = minimumSize
    }

    /// Delegates, then encodes the response body with the client's preferred coding when one is
    /// acceptable and the body is eligible.
    public func respond(
        to request: HTTPRequest,
        body: [UInt8],
        next: any HTTPResponder
    ) async -> ServerResponse {
        var response = await next.respond(to: request, body: body)
        // A streamed body is not transformed here (no streaming compression yet, P6).
        guard response.stream == nil else {
            return response
        }
        guard let coding = negotiatedCoding(request) else {
            return response
        }
        // The representation now depends on Accept-Encoding (RFC 9110 §12.5.5), even if we skip below.
        addVary(&response)
        guard isEligible(response), let encoded = compress(response.body, with: coding),
            encoded.count < response.body.count
        else {
            return response
        }
        response.body = encoded
        _ = response.head.headerFields.setValue(coding.token, for: .contentEncoding)
        _ = response.head.headerFields.setValue(String(encoded.count), for: .contentLength)
        return response
    }

    /// The coding to apply for `request`, or nil to serve the representation unencoded.
    ///
    /// The best of the codings we produce that the client accepts with a non-zero quality, preferring
    /// Brotli on a tie (RFC 9110 §12.5.3); an absent or all-zero `Accept-Encoding` yields nil (serve
    /// `identity`).
    private func negotiatedCoding(_ request: HTTPRequest) -> Coding? {
        let (explicit, wildcard) = acceptedQualities(request)
        var chosen: Coding?
        var best = 0.0
        for coding in Coding.allCases {
            let weight = explicit[coding.token] ?? wildcard ?? 0
            guard weight > best else {
                continue
            }
            chosen = coding
            best = weight
        }
        return chosen
    }

    /// Parses `Accept-Encoding` into explicit coding→quality entries plus the `*` wildcard quality, if
    /// present (RFC 9110 §12.5.3); each `q=` parameter is read by ``quality(_:)``.
    private func acceptedQualities(
        _ request: HTTPRequest
    ) -> (explicit: [String: Double], wildcard: Double?) {
        var explicit: [String: Double] = [:]
        var wildcard: Double?
        for value in request.headerFields.values(for: .acceptEncoding) {
            for element in value.split(separator: ",") {
                let parts = element.split(separator: ";")
                let coding = parts.first?.trimmingCharacters(in: .whitespaces).lowercased() ?? ""
                guard !coding.isEmpty else {
                    continue
                }
                let weight = quality(parts.dropFirst())
                if coding == "*" {
                    wildcard = weight
                }
                else {
                    explicit[coding] = weight
                }
            }
        }
        return (explicit, wildcard)
    }

    /// The `q=` value among `parameters`, defaulting to 1.0 when absent (RFC 9110 §12.4.2).
    private func quality(_ parameters: ArraySlice<Substring>) -> Double {
        for parameter in parameters {
            let token = parameter.trimmingCharacters(in: .whitespaces).lowercased()
            if token.hasPrefix("q="), let value = Double(token.dropFirst(2)) {
                return value
            }
        }
        return 1.0
    }

    /// Encodes `body` with `coding` — Darwin Brotli (RFC 7932), libzstd (RFC 8878), or gzip
    /// (RFC 1952).
    private func compress(_ body: [UInt8], with coding: Coding) -> [UInt8]? {
        switch coding {
            case .br:
                #if canImport(Compression)
                    return Brotli.compress(body)
                #elseif canImport(CBrotli)
                    return Brotli.compress(body)  // Linux: libbrotli (BrotliLinux)
                #else
                    return nil
                #endif
            #if canImport(CZstd)
                case .zstd:
                    return Zstd.compress(body)
            #endif
            case .gzip:
                #if canImport(Compression)
                    return Gzip.compress(body)
                #elseif canImport(CZlibCoding)
                    return Gzip.compress(body)  // Linux: system zlib (GzipLinux)
                #else
                    return nil
                #endif
        }
    }

    /// Whether `response` is worth compressing: large enough, not already encoded, not already-compressed media.
    private func isEligible(_ response: ServerResponse) -> Bool {
        guard response.body.count >= minimumSize else {
            return false
        }
        guard !response.head.headerFields.contains(.contentEncoding) else {
            return false
        }
        // `Cache-Control: no-transform` forbids re-encoding the payload (RFC 9110 §5.5); it is also the
        // per-response opt-out for the BREACH-class length oracle on bodies mixing a secret with
        // attacker-reflected input.
        let cacheControl = response.head.headerFields.values(for: .cacheControl)
        guard !cacheControl.contains(where: { $0.lowercased().contains("no-transform") }) else {
            return false
        }
        guard let type = response.head.headerFields[.contentType]?.lowercased() else {
            return true
        }
        return !Self.incompressible.contains { type.contains($0) }
    }

    private func addVary(_ response: inout ServerResponse) {
        let alreadyVaries = response.head.headerFields.values(for: .vary)
            .contains { $0.lowercased().contains("accept-encoding") }
        guard !alreadyVaries else {
            return
        }
        _ = response.head.headerFields.append("Accept-Encoding", for: .vary)
    }
}
