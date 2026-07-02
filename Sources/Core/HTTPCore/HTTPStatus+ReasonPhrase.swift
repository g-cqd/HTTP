//
//  HTTPStatus+ReasonPhrase.swift
//  HTTPCore
//
//  The registered reason-phrases (RFC 9110 §15 status codes, plus the extension codes this package
//  serves: RFC 6585 §3–§5 and RFC 8470 §5.2). The phrase is purely advisory — HTTP/1.1 MAY send it on
//  the status-line and a client SHOULD ignore it (RFC 9112 §4); h2/h3 dropped it entirely — but a
//  human-facing layer (logs, error pages, a downstream framework's debugging output) wants the
//  canonical text without re-typing the registry. One table serves both this public API and the
//  HTTP/1.1 status-line serializer.
//

extension HTTPStatus {
    /// The registered reason-phrase for this code (RFC 9110 §15; RFC 6585; RFC 8470), or `nil` for
    /// an unregistered code.
    ///
    /// Advisory text only: HTTP/1.1 sends it on the status-line (a client SHOULD ignore it,
    /// RFC 9112 §4) and HTTP/2/3 dropped it — never branch on it; branch on ``code``.
    public var reasonPhrase: String? { Self.reasonPhrases[code] }

    /// The registered phrases, keyed by code — a data table, no branching.
    private static let reasonPhrases: [UInt16: String] = [
        100: "Continue", 101: "Switching Protocols",
        200: "OK", 201: "Created", 202: "Accepted", 203: "Non-Authoritative Information",
        204: "No Content", 205: "Reset Content", 206: "Partial Content",
        300: "Multiple Choices", 301: "Moved Permanently", 302: "Found", 303: "See Other",
        304: "Not Modified", 307: "Temporary Redirect", 308: "Permanent Redirect",
        400: "Bad Request", 401: "Unauthorized", 402: "Payment Required", 403: "Forbidden",
        404: "Not Found", 405: "Method Not Allowed", 406: "Not Acceptable",
        407: "Proxy Authentication Required", 408: "Request Timeout", 409: "Conflict",
        410: "Gone", 411: "Length Required", 412: "Precondition Failed",
        413: "Content Too Large", 414: "URI Too Long", 415: "Unsupported Media Type",
        416: "Range Not Satisfiable", 417: "Expectation Failed", 421: "Misdirected Request",
        422: "Unprocessable Content", 425: "Too Early", 426: "Upgrade Required",
        428: "Precondition Required", 429: "Too Many Requests",
        431: "Request Header Fields Too Large", 451: "Unavailable For Legal Reasons",
        500: "Internal Server Error", 501: "Not Implemented", 502: "Bad Gateway",
        503: "Service Unavailable", 504: "Gateway Timeout", 505: "HTTP Version Not Supported"
    ]
}
