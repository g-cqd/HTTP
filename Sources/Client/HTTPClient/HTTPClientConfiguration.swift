//
//  HTTPClientConfiguration.swift
//  HTTPClient
//
//  The outbound policy of an ``HTTPClient``: identity, connection pooling, deadlines, body bounds,
//  content codings, redirect policy, and the TLS trust anchors server certificates chain to.
//

public import HTTPTLS

/// The outbound policy of an ``HTTPClient``.
public struct HTTPClientConfiguration: Sendable {
    /// Sent as `User-Agent` unless the request carries one.
    public var userAgent: String = "g-cqd-HTTP"
    /// Maximum simultaneously open connections per origin (`scheme://host:port`); further requests
    /// wait for a free connection (HTTP/1.1 carries one exchange per connection at a time).
    public var maxConnectionsPerHost: Int = 16
    /// Maximum idle keep-alive connections retained per origin.
    public var maxIdleConnectionsPerHost: Int = 16
    /// How long an idle keep-alive connection may be reused.
    public var idleTimeout: Duration = .seconds(30)
    /// Deadline for resolve + TCP connect + TLS handshake.
    public var connectTimeout: Duration = .seconds(15)
    /// Deadline for one whole exchange (connect, request, response head and body).
    public var requestTimeout: Duration = .seconds(60)
    /// Upper bound on the response body, both on the wire and after content decoding.
    public var maxResponseBodyBytes: Int = 64 * 1_024 * 1_024
    /// Advertise and decode `zstd` / `gzip` / `deflate` content codings (RFC 9110 §8.4).
    public var automaticDecompression = true
    /// Maximum redirects followed for `GET` / `HEAD` (`0` disables following).
    public var maxRedirects: Int = 5
    /// Approves each redirect target (`scheme`, `host`, `port`); default refuses HTTPS → HTTP downgrades.
    public var redirectFilter:
        @Sendable (_ scheme: String, _ host: String, _ port: UInt16) -> Bool = {
            scheme, _, _ in scheme == "https"
        }
    /// Trust anchors server certificates must chain to; `nil` loads the platform PEM bundle once.
    public var trustAnchors: TLSTrustAnchors?

    /// Creates the default configuration.
    public init() {
        // Every policy has a property default above.
    }
}
