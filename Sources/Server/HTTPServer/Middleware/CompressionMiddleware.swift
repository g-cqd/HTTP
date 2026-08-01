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
//  A streamed body is coded incrementally through a ``CompressingBodyWriter`` interposed between the
//  producer and the engine's writer, so nothing is buffered to code it; `Content-Length` is removed
//  (the coded length is not knowable ahead of the body) and h1 frames it chunked. A coding whose
//  backend has no incremental form declines rather than buffering — see ``StreamingContentEncoder``.
//

internal import Foundation
public import HTTPCore

/// Compresses eligible responses with the client's preferred content coding — Brotli or gzip
/// (RFC 9110 §8.4.1).
public struct CompressionMiddleware: HTTPMiddleware {
    private let minimumSize: Int
    private let encoders: [any ContentEncoder]

    /// Media-type fragments whose payloads are already compressed — re-encoding only adds overhead.
    private static let incompressible = [
        "image/", "video/", "audio/", "zip", "gzip", "brotli", "zstd", "compress"
    ]

    /// The built-in content codings in server-preference order — Brotli (RFC 7932), then zstd (RFC 8878,
    /// only when the opt-in `CZstd` shim is present), then gzip (RFC 1952).
    ///
    /// Each coding is included only on a build that can actually produce it, so the negotiator never
    /// offers one it cannot encode; the order is the br > zstd > gzip tie-break it applies on equal
    /// q-values (RFC 9110 §12.5.3).
    public static var defaultEncoders: [any ContentEncoder] {
        var encoders: [any ContentEncoder] = []
        #if canImport(Compression) || canImport(CBrotli)
            encoders.append(BrotliEncoder())
        #endif
        #if canImport(CZstd)
            encoders.append(ZstdEncoder())
        #endif
        #if canImport(Compression) || canImport(CZlibCoding)
            encoders.append(GzipEncoder())
        #endif
        return encoders
    }

    /// Creates the middleware; responses below `minimumSize` octets are not compressed (default 1 KiB,
    /// since tiny bodies cost more in framing overhead than they save).
    ///
    /// `encoders` are the content codings to offer, tried in order (the earlier-listed one wins a q-value
    /// tie); a `nil` (the default) uses the platform's built-in ``defaultEncoders`` (Brotli / zstd / gzip).
    public init(
        minimumSize: Int = 1_024,
        encoders: [any ContentEncoder]? = nil
    ) {
        self.minimumSize = minimumSize
        self.encoders = encoders ?? Self.defaultEncoders
    }

    /// Delegates, then encodes the response body with the client's preferred coding when one is
    /// acceptable and the body is eligible.
    public func respond(
        to request: HTTPRequest,
        body: RequestBody,
        context: RequestContext,
        next: any HTTPResponder
    ) async -> ServerResponse {
        var response = await next.respond(to: request, body: body, context: context)
        guard let encoder = negotiatedEncoder(request) else {
            return response
        }
        // The representation now depends on Accept-Encoding (RFC 9110 §12.5.5), even if we skip below.
        // Set before either path branches, so a streamed and a buffered representation of the same
        // resource carry byte-identical `Vary` and a cache cannot key them differently.
        addVary(&response)
        if let stream = response.stream {
            return coded(response, stream: stream, with: encoder)
        }
        guard isEligible(response), response.body.count >= minimumSize,
            let encoded = encoder.encode(response.body), encoded.count < response.body.count
        else {
            return response
        }
        response.body = encoded
        _ = response.head.headerFields.setValue(encoder.token, for: .contentEncoding)
        _ = response.head.headerFields.setValue(String(encoded.count), for: .contentLength)
        return response
    }

    /// `response` with its streamed body coded incrementally, or unchanged when it cannot be.
    ///
    /// Three ways to decline, each leaving the body streaming uncoded rather than buffering it: the
    /// coding has no incremental backend on this build, the representation is not transformable, or the
    /// body announces a length below ``minimumSize``. A body of *unknown* length is coded — not knowing
    /// how big it is, is the reason it is streaming.
    private func coded(
        _ response: ServerResponse,
        stream: ResponseStream,
        with encoder: any ContentEncoder
    ) -> ServerResponse {
        guard let streaming = encoder as? any StreamingContentEncoder,
            isEligible(response), stream.contentLength.map({ $0 >= minimumSize }) ?? true,
            let coder = streaming.makeStream()
        else {
            return response
        }
        var response = response
        let coding = ContentCodingSession(coder)
        response.stream = ResponseStream { writer in
            // Runs on every exit, so a client that disconnects mid-body frees the codec here rather
            // than whenever the last reference to this closure happens to go.
            defer { coding.release() }
            let compressing = CompressingBodyWriter(coding: coding, downstream: writer)
            try await stream.produce(compressing)
            try await compressing.finish()
        }
        _ = response.head.headerFields.setValue(encoder.token, for: .contentEncoding)
        // The coded length is not knowable ahead of the body, and the h1 engine frames a stream chunked
        // precisely when `contentLength` is nil — but it does *not* strip a stale `Content-Length`, and
        // a response carrying both is the RFC 9112 §6.1 request-smuggling shape. Remove it here.
        response.head.headerFields.removeAll(named: .contentLength)
        return response
    }

    /// The encoder to apply for `request`, or nil to serve the representation unencoded.
    ///
    /// The best of the codings we produce that the client accepts with a non-zero quality, preferring the
    /// earlier-listed encoder on a tie (RFC 9110 §12.5.3); an absent or all-zero `Accept-Encoding` yields
    /// nil (serve `identity`).
    private func negotiatedEncoder(_ request: HTTPRequest) -> (any ContentEncoder)? {
        let (explicit, wildcard) = acceptedQualities(request)
        var chosen: (any ContentEncoder)?
        var best = 0.0
        for encoder in encoders {
            let weight = explicit[encoder.token] ?? wildcard ?? 0
            guard weight > best else {
                continue
            }
            chosen = encoder
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

    /// Whether the representation carried by `response` may be re-encoded at all.
    ///
    /// Not already coded, not `no-transform`, and not an already-compressed media type.
    ///
    /// Size is deliberately not checked here — a streamed body may not know its own length, so each
    /// path applies ``minimumSize`` to whatever length it actually has.
    private func isEligible(_ response: ServerResponse) -> Bool {
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
