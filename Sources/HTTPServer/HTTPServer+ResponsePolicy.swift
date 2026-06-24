//
//  HTTPServer+ResponsePolicy.swift
//  HTTPServer
//
//  The HTTP/1.1 error-response and connection-close policy helpers, extracted from HTTPServer: map a
//  parse failure to its status (RFC 9110 §15), emit a fail-closed error response (RFC 9112 §9.6), and
//  decide whether the connection persists after an exchange (RFC 9110 §7.6.1 / RFC 9112 §9.3).
//

internal import HTTP1
internal import HTTPCore
internal import HTTPTransport

extension HTTPServer {
    func sendErrorResponse(
        for error: HTTP1ParseError,
        to connection: any TransportConnection
    ) async {
        var response = HTTPResponse(status: Self.status(for: error))
        // The server fails closed on a parse error, so it tells the peer (RFC 9112 §9.6).
        response.headerFields.append("close", for: .connection)
        let bytes = ResponseSerializer.serialize(response)
        try? await connection.send(bytes)
    }

    /// Maps a parse error to the response status it should produce (RFC 9110 §15).
    private static func status(for error: HTTP1ParseError) -> HTTPStatus {
        switch error {
            case .requestLineTooLong:
                .uriTooLong
            case .fieldTooLarge, .headerSectionTooLarge, .tooManyFields:
                .requestHeaderFieldsTooLarge
            case .bodyTooLarge:
                .contentTooLarge
            case .unsupportedVersion:
                .httpVersionNotSupported
            case .unsupportedTransferEncoding:
                // A transfer coding the server doesn't understand (RFC 9112 §6.1; audit H1-F5).
                .notImplemented
            default:
                .badRequest
        }
    }

    /// Whether the connection must close after this exchange.
    ///
    /// An explicit `close` connection-option on either message always ends persistence (RFC 9110
    /// §7.6.1). Otherwise the default follows the request version (RFC 9112 §9.3): HTTP/1.1 persists,
    /// while HTTP/1.0 closes unless the request asked to `keep-alive`.
    static func shouldClose(
        version: HTTPVersion,
        request: HTTPRequest,
        response: HTTPResponse
    ) -> Bool {
        if connectionContains(request.headerFields, "close")
            || connectionContains(response.headerFields, "close")
        {
            return true
        }
        if version.major == 1, version.minor >= 1 {
            return false
        }
        return !connectionContains(request.headerFields, "keep-alive")
    }

    /// Whether the `Connection` field's comma-separated list contains `option` (case-insensitive,
    /// OWS-trimmed) — RFC 9110 §7.6.1.
    private static func connectionContains(_ fields: HTTPFields, _ option: String) -> Bool {
        guard let value = fields[.connection] else {
            return false
        }
        return value.split(separator: ",").contains { normalizedToken($0) == option }
    }

    private static func normalizedToken(_ option: Substring) -> String {
        option.lowercased().filter { $0 != " " && $0 != "\t" }
    }
}
