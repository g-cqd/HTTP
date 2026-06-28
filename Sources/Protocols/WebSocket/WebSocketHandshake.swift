//
//  WebSocketHandshake.swift
//  WebSocket
//
//  RFC 6455 §4 — the server side of the opening handshake. A pure function: it validates a client's
//  HTTP/1.1 Upgrade request (§4.2.1) and produces the `101 Switching Protocols` response (§4.2.2),
//  whose `Sec-WebSocket-Accept` is base64(SHA-1(key ‖ GUID)). No I/O; runs once per connection.
//

internal import Foundation
public import HTTPCore

/// The server half of the RFC 6455 §4 opening handshake (request validation + the 101 response).
public enum WebSocketHandshake {
    /// The §1.3 globally-unique identifier concatenated with the client key to derive the accept hash.
    private static let guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    /// Validates `request` as a WebSocket upgrade and returns the 101 response (RFC 6455 §4.2).
    ///
    /// Checks the method, the `Upgrade`/`Connection` tokens, the version (13), and the base64 key
    /// (§4.2.1); on success returns `101 Switching Protocols` carrying `Upgrade`, `Connection`, and
    /// the derived `Sec-WebSocket-Accept` (§4.2.2). Throws the specific reason it is not a valid
    /// upgrade, which carries the status to reject with.
    public static func response(
        to request: HTTPRequest
    ) throws(WebSocketHandshakeError) -> HTTPResponse {
        guard request.method == .get else { throw .methodNotGet }
        guard containsToken(request.headerFields, .upgrade, "websocket") else {
            throw .missingUpgrade
        }
        guard containsToken(request.headerFields, .connection, "upgrade") else {
            throw .missingConnectionUpgrade
        }
        guard request.headerFields[.secWebSocketVersion] == "13" else { throw .unsupportedVersion }
        guard let key = request.headerFields[.secWebSocketKey], isValidKey(key) else {
            throw .missingOrInvalidKey
        }

        var fields = HTTPFields()
        _ = fields.append("websocket", for: .upgrade)
        _ = fields.append("Upgrade", for: .connection)
        _ = fields.append(accept(for: key), for: .secWebSocketAccept)
        // RFC 7692 §5.1 — accept a permessage-deflate offer we can satisfy by echoing our negotiated
        // parameters in the 101; the same call tells the driver to enable it on the connection.
        if let parameters = negotiatePermessageDeflate(request.headerFields) {
            _ = fields.append(parameters.headerValue, for: .secWebSocketExtensions)
        }
        return HTTPResponse(status: .switchingProtocols, headerFields: fields)
    }

    /// Negotiates permessage-deflate against the client's `Sec-WebSocket-Extensions` offer, or nil if
    /// none is offered or it cannot be satisfied (RFC 7692 §5.1 / §7.1).
    ///
    /// We use a full (15-bit) window, so an offer that pins `server_max_window_bits` smaller is declined
    /// (falling back to an uncompressed connection). The context-takeover knobs are honored: the
    /// client's `server_no_context_takeover` forces our compressor to reset per message, and its
    /// `client_no_context_takeover` is echoed (our decompressor resets per message); absent both, each
    /// direction uses context-takeover. `client_max_window_bits` — the common browser offer — is ignored.
    public static func negotiatePermessageDeflate(
        _ fields: HTTPFields
    ) -> PermessageDeflateParameters? {
        for value in fields.values(for: .secWebSocketExtensions) {
            for offer in value.split(separator: ",") {
                var params = offer.split(separator: ";")
                    .map { $0.trimmingCharacters(in: .whitespaces) }
                guard params.first == "permessage-deflate" else { continue }
                params.removeFirst()
                if params.contains(where: { $0.hasPrefix("server_max_window_bits") }) { continue }
                return PermessageDeflateParameters(
                    serverNoContextTakeover: params.contains("server_no_context_takeover"),
                    clientNoContextTakeover: params.contains("client_no_context_takeover")
                )
            }
        }
        return nil
    }

    /// `Sec-WebSocket-Accept` for a client key: base64(SHA-1(key ‖ GUID)) (RFC 6455 §4.2.2).
    public static func accept(for key: String) -> String {
        Base64.encode(SHA1.hash(Array((key + guid).utf8)), alphabet: .standard, padded: true)
    }

    /// Whether `fields[name]` offers `token`, case-insensitively, within its comma-separated list
    /// (RFC 9110 §5.6.1) — how `Upgrade` and `Connection` carry their tokens.
    private static func containsToken(
        _ fields: HTTPFields,
        _ name: HTTPFieldName,
        _ token: String
    ) -> Bool {
        for value in fields.values(for: name) {
            for element in value.split(separator: ",")
            where element.trimmingCharacters(in: .whitespaces).lowercased() == token {
                return true
            }
        }
        return false
    }

    /// Whether `key` is a base64 encoding of exactly 16 octets (RFC 6455 §4.1).
    private static func isValidKey(_ key: String) -> Bool {
        Base64.decode(key, alphabet: .standard, padded: true)?.count == 16
    }
}
