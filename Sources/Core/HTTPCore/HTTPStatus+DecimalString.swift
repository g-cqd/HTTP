//
//  HTTPStatus+DecimalString.swift
//  HTTPCore
//
//  The status code as a decimal string for the `:status` pseudo-header (HTTP/2 RFC 9113 §8.3,
//  HTTP/3 RFC 9114 §4.1). Cached for the common codes so a response's `:status` value costs no
//  allocation on the encode hot path — shared by the HPACK and QPACK response encoders.
//

extension HTTPStatus {
    /// The status code as a decimal string (e.g. `"200"`), for the `:status` pseudo-header.
    ///
    /// Cached for the common codes — those small literals are stored inline, so a response's `:status`
    /// value costs no heap allocation; an uncommon code falls back to `String(code)`.
    public var decimalString: String {
        Self.cachedDecimalStrings[code] ?? String(code)
    }

    /// Decimal strings for the common status codes (see ``decimalString``).
    private static let cachedDecimalStrings: [UInt16: String] = [
        100: "100", 101: "101",
        200: "200", 201: "201", 202: "202", 204: "204", 206: "206",
        301: "301", 302: "302", 304: "304", 307: "307", 308: "308",
        400: "400", 401: "401", 403: "403", 404: "404", 405: "405", 409: "409",
        413: "413", 416: "416", 429: "429",
        500: "500", 501: "501", 502: "502", 503: "503", 504: "504"
    ]
}
