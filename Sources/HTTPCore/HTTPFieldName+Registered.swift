//
//  HTTPFieldName+Registered.swift
//  HTTPCore
//
//  Commonly used field names from the IANA HTTP Field Name Registry. Stored in canonical
//  (lower-case) form. Any other valid token can be created via `HTTPFieldName(_:)`.
//

extension HTTPFieldName {
    // MARK: Message routing & framing

    /// `Host` (RFC 9110 §7.2).
    public static let host = HTTPFieldName(unchecked: "host")
    /// `Connection` (RFC 9110 §7.6.1) — a connection-specific field, forbidden in HTTP/2 & HTTP/3.
    public static let connection = HTTPFieldName(unchecked: "connection")
    /// `Content-Length` (RFC 9110 §8.6).
    public static let contentLength = HTTPFieldName(unchecked: "content-length")
    /// `Transfer-Encoding` (RFC 9112 §6.1).
    public static let transferEncoding = HTTPFieldName(unchecked: "transfer-encoding")
    /// `Upgrade` (RFC 9110 §7.8) — used by the WebSocket handshake.
    public static let upgrade = HTTPFieldName(unchecked: "upgrade")

    // MARK: Representation metadata

    /// `Content-Type` (RFC 9110 §8.3).
    public static let contentType = HTTPFieldName(unchecked: "content-type")
    /// `Content-Encoding` (RFC 9110 §8.4).
    public static let contentEncoding = HTTPFieldName(unchecked: "content-encoding")
    /// `Vary` (RFC 9110 §12.5.5).
    public static let vary = HTTPFieldName(unchecked: "vary")

    // MARK: Content negotiation

    /// `Accept` (RFC 9110 §12.5.1).
    public static let accept = HTTPFieldName(unchecked: "accept")
    /// `Accept-Encoding` (RFC 9110 §12.5.3).
    public static let acceptEncoding = HTTPFieldName(unchecked: "accept-encoding")

    // MARK: Caching & conditionals

    /// `Cache-Control` (RFC 9111 §5.2).
    public static let cacheControl = HTTPFieldName(unchecked: "cache-control")
    /// `ETag` (RFC 9110 §8.8.3).
    public static let etag = HTTPFieldName(unchecked: "etag")

    // MARK: General & response metadata

    /// `Date` (RFC 9110 §6.6.1).
    public static let date = HTTPFieldName(unchecked: "date")
    /// `Server` (RFC 9110 §10.2.4).
    public static let server = HTTPFieldName(unchecked: "server")
    /// `Location` (RFC 9110 §10.2.2).
    public static let location = HTTPFieldName(unchecked: "location")
    /// `Alt-Svc` (RFC 7838) — advertises alternative services such as HTTP/3.
    public static let altSvc = HTTPFieldName(unchecked: "alt-svc")

    // MARK: Authentication & state

    /// `Authorization` (RFC 9110 §11.6.2).
    public static let authorization = HTTPFieldName(unchecked: "authorization")
    /// `Cookie` (RFC 6265 §5.4).
    public static let cookie = HTTPFieldName(unchecked: "cookie")
    /// `Set-Cookie` (RFC 6265 §5.2).
    public static let setCookie = HTTPFieldName(unchecked: "set-cookie")
    /// `User-Agent` (RFC 9110 §10.1.5).
    public static let userAgent = HTTPFieldName(unchecked: "user-agent")

    // MARK: WebSocket handshake (RFC 6455 §4.1 / §4.2)

    /// `Sec-WebSocket-Key` (RFC 6455 §4.1) — the client's base64 nonce.
    public static let secWebSocketKey = HTTPFieldName(unchecked: "sec-websocket-key")
    /// `Sec-WebSocket-Accept` (RFC 6455 §4.2.2) — the server's handshake confirmation hash.
    public static let secWebSocketAccept = HTTPFieldName(unchecked: "sec-websocket-accept")
    /// `Sec-WebSocket-Version` (RFC 6455 §4.1) — the negotiated WebSocket version (13).
    public static let secWebSocketVersion = HTTPFieldName(unchecked: "sec-websocket-version")

    // MARK: CORS (WHATWG Fetch — Cross-Origin Resource Sharing)

    /// `Origin` (RFC 6454 §7) — the request's origin; also checked to defend WebSocket upgrades
    /// against cross-site hijacking (RFC 6455 §10.2, CWE-1385).
    public static let origin = HTTPFieldName(unchecked: "origin")
    /// `Access-Control-Request-Method` — the method a CORS preflight asks about.
    public static let accessControlRequestMethod = HTTPFieldName(
        unchecked: "access-control-request-method"
    )
    /// `Access-Control-Request-Headers` — the headers a CORS preflight asks about.
    public static let accessControlRequestHeaders = HTTPFieldName(
        unchecked: "access-control-request-headers"
    )
    /// `Access-Control-Allow-Origin` — the origin(s) the server permits.
    public static let accessControlAllowOrigin = HTTPFieldName(
        unchecked: "access-control-allow-origin"
    )
    /// `Access-Control-Allow-Methods` — the methods the server permits cross-origin.
    public static let accessControlAllowMethods = HTTPFieldName(
        unchecked: "access-control-allow-methods"
    )
    /// `Access-Control-Allow-Headers` — the request headers the server permits cross-origin.
    public static let accessControlAllowHeaders = HTTPFieldName(
        unchecked: "access-control-allow-headers"
    )
    /// `Access-Control-Allow-Credentials` — whether credentials may accompany the request.
    public static let accessControlAllowCredentials = HTTPFieldName(
        unchecked: "access-control-allow-credentials"
    )
    /// `Access-Control-Max-Age` — how long a preflight result may be cached.
    public static let accessControlMaxAge = HTTPFieldName(unchecked: "access-control-max-age")

    // MARK: Conditional requests (RFC 9110 §13)

    /// `If-None-Match` (RFC 9110 §13.1.2) — the validators a cache holds; matches make a 304.
    public static let ifNoneMatch = HTTPFieldName(unchecked: "if-none-match")
    /// `If-Modified-Since` (RFC 9110 §13.1.3).
    public static let ifModifiedSince = HTTPFieldName(unchecked: "if-modified-since")
    /// `Last-Modified` (RFC 9110 §8.8.2).
    public static let lastModified = HTTPFieldName(unchecked: "last-modified")

    // MARK: Security response headers (WHATWG / RFC 6797 / W3C)

    /// `Strict-Transport-Security` (RFC 6797) — pins the client to HTTPS for a duration.
    public static let strictTransportSecurity = HTTPFieldName(
        unchecked: "strict-transport-security"
    )
    /// `X-Content-Type-Options` — `nosniff` stops content-type sniffing.
    public static let xContentTypeOptions = HTTPFieldName(unchecked: "x-content-type-options")
    /// `X-Frame-Options` — legacy clickjacking defense (framing policy).
    public static let xFrameOptions = HTTPFieldName(unchecked: "x-frame-options")
    /// `Referrer-Policy` (W3C) — controls the `Referer` sent to other origins.
    public static let referrerPolicy = HTTPFieldName(unchecked: "referrer-policy")
    /// `Content-Security-Policy` (W3C CSP) — restricts the resources a page may load.
    public static let contentSecurityPolicy = HTTPFieldName(unchecked: "content-security-policy")
}
