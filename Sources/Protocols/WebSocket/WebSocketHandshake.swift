//
//  WebSocketHandshake.swift
//  WebSocket
//
//  RFC 6455 §4 — the server side of the opening handshake. A pure function: it validates a client's
//  HTTP/1.1 Upgrade request (§4.2.1) and produces the `101 Switching Protocols` response (§4.2.2),
//  whose `Sec-WebSocket-Accept` is base64(SHA-1(key ‖ GUID)). No I/O; runs once per connection.
//

internal import CryptoKit
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
        // RFC 7692 §5.1 — accept a permessage-deflate offer we can satisfy by echoing our chosen
        // parameters in the 101; the same predicate tells the driver to enable it on the connection.
        if negotiatesPermessageDeflate(request.headerFields) {
            _ = fields.append(extensionResponse, for: .secWebSocketExtensions)
        }
        return HTTPResponse(status: .switchingProtocols, headerFields: fields)
    }

    /// The `Sec-WebSocket-Extensions` value we accept a permessage-deflate offer with (RFC 7692 §5.1):
    /// `no_context_takeover` in both directions, so every message is an independent DEFLATE stream.
    public static let extensionResponse =
        "permessage-deflate; server_no_context_takeover; client_no_context_takeover"

    /// Whether the client's `Sec-WebSocket-Extensions` offers a permessage-deflate we can satisfy with a
    /// full (15-bit) window and `no_context_takeover` (RFC 7692 §5.1 / §7.1).
    ///
    /// An offer that pins `server_max_window_bits` to a smaller window is declined (Apple's Compression
    /// uses a fixed 15-bit window, RFC 7692 §7.1.2.1), falling back to an uncompressed connection;
    /// `client_max_window_bits` — the common browser offer — is accepted (it only permits the client a
    /// smaller window, which `client_no_context_takeover` already supersedes).
    public static func negotiatesPermessageDeflate(_ fields: HTTPFields) -> Bool {
        for value in fields.values(for: .secWebSocketExtensions) {
            for offer in value.split(separator: ",") {
                var params = offer.split(separator: ";")
                    .map { $0.trimmingCharacters(in: .whitespaces) }
                guard params.first == "permessage-deflate" else { continue }
                params.removeFirst()
                if params.contains(where: { $0.hasPrefix("server_max_window_bits") }) { continue }
                return true
            }
        }
        return false
    }

    /// `Sec-WebSocket-Accept` for a client key: base64(SHA-1(key ‖ GUID)) (RFC 6455 §4.2.2).
    public static func accept(for key: String) -> String {
        var hasher = Insecure.SHA1()
        hasher.update(data: Data((key + guid).utf8))
        return Data(hasher.finalize()).base64EncodedString()
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
        Data(base64Encoded: key)?.count == 16
    }
}
