//
//  HTTPClient.swift
//  HTTPClient
//
//  The outbound HTTP/1.1 client: pooled keep-alive connections over the POSIX transport backbones
//  (kqueue / epoll) with the in-house TLS 1.3 client (swift-crypto + swift-certificates, no
//  OpenSSL, no URLSession / FoundationNetworking), RFC 9112 framing, RFC 9110 content decoding
//  (zstd, gzip, deflate), deadlines, one retry of idempotent requests on stale keep-alive
//  connections, and policy-filtered redirects.
//

internal import HTTP1
internal import HTTPConcurrency
public import HTTPCore

/// An outbound HTTP/1.1 client with per-origin keep-alive pooling.
public final class HTTPClient: Sendable {
    /// The client's outbound policy.
    public let configuration: HTTPClientConfiguration
    private let pool: HTTPConnectionPool
    private let limits: HTTPLimits

    deinit {
        // Pooled connections close when the pool actor is released; call ``shutdown()`` to close
        // them deterministically.
    }

    /// Creates a client; connections are opened lazily per origin.
    public init(configuration: HTTPClientConfiguration = HTTPClientConfiguration()) {
        self.configuration = configuration
        self.pool = HTTPConnectionPool(configuration: configuration)
        let bodyBound = max(1, configuration.maxResponseBodyBytes)
        self.limits = HTTPLimits.default.with { draft in
            draft.maxBodySize = bodyBound
            draft.maxDecompressedBodySize = bodyBound
        }
    }

    /// Fetches `url` (`http` / `https`, absolute) with `headers`.
    public func get(
        _ url: String,
        headers: HTTPFields = HTTPFields()
    ) async throws(HTTPClientError) -> HTTPClientResponse {
        let target = try HTTPClientURL(url)
        return try await execute(
            HTTPRequest(
                method: .get,
                scheme: target.scheme,
                authority: target.authority,
                path: target.path,
                headerFields: headers
            )
        )
    }

    /// Performs `request` (absolute-form: `scheme` + `authority` + origin-form `path`) with `body`,
    /// following redirects for `GET` / `HEAD` and decoding the response's content codings.
    public func execute(
        _ request: HTTPRequest,
        body: [UInt8] = []
    ) async throws(HTTPClientError) -> HTTPClientResponse {
        do {
            return try await withDeadline(configuration.requestTimeout) {
                try await self.follow(request, body: body)
            }
        }
        catch let error as HTTPClientError {
            throw error
        }
        catch is CancellationError {
            throw .cancelled
        }
        catch {
            throw .connectFailed("\(error)")
        }
    }

    /// Closes every pooled connection; further requests fail with ``HTTPClientError/connectionClosed``.
    public func shutdown() async {
        await pool.shutdown()
    }

    private func follow(_ initial: HTTPRequest, body: [UInt8]) async throws -> HTTPClientResponse {
        var request = initial
        var redirects = 0
        while true {
            let origin = try HTTPOrigin(
                scheme: request.scheme,
                authority: request.effectiveAuthority
            )
            let raw = try await perform(request, body: body, origin: origin)
            let status = raw.head.response.status
            let fields = raw.head.response.headerFields
            let followable = request.method == .get || request.method == .head
            if followable, [301, 302, 303, 307, 308].contains(status.code),
                let location = fields[.location]
            {
                guard redirects < configuration.maxRedirects else {
                    throw HTTPClientError.redirectRefused(
                        "more than \(configuration.maxRedirects) redirects"
                    )
                }
                redirects += 1
                let next = try HTTPClientURL(location, relativeTo: origin, path: request.path)
                let nextOrigin = try HTTPOrigin(scheme: next.scheme, authority: next.authority)
                guard
                    configuration.redirectFilter(
                        nextOrigin.scheme,
                        nextOrigin.host,
                        nextOrigin.port
                    )
                else {
                    throw HTTPClientError.redirectRefused("\(nextOrigin)")
                }
                var nextFields = request.headerFields
                if nextOrigin != origin {
                    nextFields.removeAll(named: .authorization)
                    nextFields.removeAll(named: .cookie)
                }
                nextFields.removeAll(named: .host)
                request = HTTPRequest(
                    method: request.method,
                    scheme: next.scheme,
                    authority: next.authority,
                    path: next.path,
                    headerFields: nextFields
                )
                continue
            }
            return try decoded(raw, method: request.method)
        }
    }

    private func decoded(
        _ raw: HTTPClientConnection.RawResponse, method: HTTPMethod
    ) throws -> HTTPClientResponse {
        let fields = raw.head.response.headerFields
        var body = raw.body
        let encodings = fields.values(for: .contentEncoding)
        if !encodings.isEmpty, !body.isEmpty, method != .head {
            body = try ContentCodings.decode(
                body,
                encodings: encodings,
                maxOutput: limits.maxBodySize
            )
        }
        return HTTPClientResponse(
            status: raw.head.response.status,
            headerFields: fields,
            body: body
        )
    }

    /// One exchange on a pooled connection; an idempotent request that finds a reused keep-alive
    /// connection already closed by the server is retried once on a fresh dial (RFC 9112 §9.3.1).
    private func perform(
        _ request: HTTPRequest,
        body: [UInt8],
        origin: HTTPOrigin
    ) async throws -> HTTPClientConnection.RawResponse {
        let bytes = try serialize(request, body: body, origin: origin)
        let idempotent = [.get, .head, .put, .delete, .options].contains(request.method)
        var attempt = 0
        while true {
            attempt += 1
            let (connection, fresh) = try await withDeadline(configuration.connectTimeout) {
                try await self.pool.lease(origin)
            }
            do {
                let raw = try await connection.exchange(
                    bytes,
                    method: request.method,
                    limits: limits
                )
                await pool.release(connection)
                return raw
            }
            catch {
                connection.abort()
                await connection.close()
                await pool.release(connection)
                let stale = (error as? HTTPClientError) == .connectionClosed
                if stale, !fresh, idempotent, attempt == 1 {
                    continue
                }
                throw error
            }
        }
    }

    private func serialize(
        _ request: HTTPRequest, body: [UInt8], origin: HTTPOrigin
    ) throws -> [UInt8] {
        var fields = request.headerFields
        fields.removeAll(named: .host)
        if !fields.contains(.userAgent) {
            _ = fields.append(configuration.userAgent, for: .userAgent)
        }
        if configuration.automaticDecompression, !fields.contains(.acceptEncoding) {
            _ = fields.append(ContentCodings.acceptEncoding, for: .acceptEncoding)
        }
        let wire = HTTPRequest(
            method: request.method,
            scheme: origin.scheme,
            authority: origin.hostHeader,
            path: request.path,
            headerFields: fields
        )
        do {
            return try RequestSerializer.serialize(wire, body: body)
        }
        catch {
            throw HTTPClientError.invalidRequest("\(error)")
        }
    }
}

/// Runs `operation`, cancelling it and throwing ``HTTPClientError/timedOut`` after `limit` on `clock`.
func withDeadline<T: Sendable>(
    _ limit: Duration,
    clock: some Clock<Duration> = ContinuousClock(),
    _ operation: @escaping @Sendable () async throws -> T
) async throws -> T {
    do {
        return try await withTimeLimit(limit, clock: clock, operation)
    }
    catch is TimeLimitExceeded {
        throw HTTPClientError.timedOut
    }
}
