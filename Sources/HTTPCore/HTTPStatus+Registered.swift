//
//  HTTPStatus+Registered.swift
//  HTTPCore
//
//  Commonly used status codes from the IANA HTTP Status Code Registry (RFC 9110 §15).
//  This is a curated subset; any valid code may still be created via `HTTPStatus(code:)`.
//

extension HTTPStatus {

    // MARK: 1xx Informational

    /// `100 Continue` (RFC 9110 §15.2.1).
    public static let `continue` = HTTPStatus(unchecked: 100)
    /// `101 Switching Protocols` (RFC 9110 §15.2.2) — used by the WebSocket upgrade.
    public static let switchingProtocols = HTTPStatus(unchecked: 101)

    // MARK: 2xx Successful

    /// `200 OK` (RFC 9110 §15.3.1).
    public static let ok = HTTPStatus(unchecked: 200)
    /// `201 Created` (RFC 9110 §15.3.2).
    public static let created = HTTPStatus(unchecked: 201)
    /// `202 Accepted` (RFC 9110 §15.3.3).
    public static let accepted = HTTPStatus(unchecked: 202)
    /// `204 No Content` (RFC 9110 §15.3.5).
    public static let noContent = HTTPStatus(unchecked: 204)

    // MARK: 3xx Redirection

    /// `301 Moved Permanently` (RFC 9110 §15.4.2).
    public static let movedPermanently = HTTPStatus(unchecked: 301)
    /// `302 Found` (RFC 9110 §15.4.3).
    public static let found = HTTPStatus(unchecked: 302)
    /// `304 Not Modified` (RFC 9110 §15.4.5).
    public static let notModified = HTTPStatus(unchecked: 304)

    // MARK: 4xx Client Error

    /// `400 Bad Request` (RFC 9110 §15.5.1).
    public static let badRequest = HTTPStatus(unchecked: 400)
    /// `401 Unauthorized` (RFC 9110 §15.5.2).
    public static let unauthorized = HTTPStatus(unchecked: 401)
    /// `403 Forbidden` (RFC 9110 §15.5.4).
    public static let forbidden = HTTPStatus(unchecked: 403)
    /// `404 Not Found` (RFC 9110 §15.5.5).
    public static let notFound = HTTPStatus(unchecked: 404)
    /// `405 Method Not Allowed` (RFC 9110 §15.5.6).
    public static let methodNotAllowed = HTTPStatus(unchecked: 405)
    /// `408 Request Timeout` (RFC 9110 §15.5.9) — emitted on Slowloris header/body timeouts.
    public static let requestTimeout = HTTPStatus(unchecked: 408)
    /// `413 Content Too Large` (RFC 9110 §15.5.14).
    public static let contentTooLarge = HTTPStatus(unchecked: 413)
    /// `414 URI Too Long` (RFC 9110 §15.5.15).
    public static let uriTooLong = HTTPStatus(unchecked: 414)
    /// `426 Upgrade Required` (RFC 9110 §15.5.22) — rejects a WebSocket handshake naming a version.
    public static let upgradeRequired = HTTPStatus(unchecked: 426)
    /// `429 Too Many Requests` (RFC 6585 §4).
    public static let tooManyRequests = HTTPStatus(unchecked: 429)
    /// `431 Request Header Fields Too Large` (RFC 6585 §5).
    public static let requestHeaderFieldsTooLarge = HTTPStatus(unchecked: 431)

    // MARK: 5xx Server Error

    /// `500 Internal Server Error` (RFC 9110 §15.6.1).
    public static let internalServerError = HTTPStatus(unchecked: 500)
    /// `501 Not Implemented` (RFC 9110 §15.6.2).
    public static let notImplemented = HTTPStatus(unchecked: 501)
    /// `502 Bad Gateway` (RFC 9110 §15.6.3).
    public static let badGateway = HTTPStatus(unchecked: 502)
    /// `503 Service Unavailable` (RFC 9110 §15.6.4).
    public static let serviceUnavailable = HTTPStatus(unchecked: 503)
    /// `505 HTTP Version Not Supported` (RFC 9110 §15.6.6).
    public static let httpVersionNotSupported = HTTPStatus(unchecked: 505)
}
