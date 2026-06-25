//
//  WebSocketHandshakeTests.swift
//  WebSocketTests
//
//  RFC 6455 §4 — the opening handshake: the §1.3 Sec-WebSocket-Accept test vector, a full 101
//  response, and rejection of each malformed upgrade (§4.2.1).
//

import HTTPCore
import Testing

@testable import WebSocket

@Suite("RFC 6455 §4 — opening handshake")
struct WebSocketHandshakeTests {
    @Test("derives Sec-WebSocket-Accept from the RFC 6455 §1.3 example key")
    func acceptMatchesRFCVector() {
        // RFC 6455 §1.3: key "dGhlIHNhbXBsZSBub25jZQ==" → "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=".
        #expect(
            WebSocketHandshake.accept(for: "dGhlIHNhbXBsZSBub25jZQ==")
                == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
    }

    @Test("a valid upgrade yields 101 with the handshake headers")
    func validUpgradeProduces101() throws {
        let response = try WebSocketHandshake.response(to: upgradeRequest())
        #expect(response.status == .switchingProtocols)
        #expect(response.headerFields[.upgrade] == "websocket")
        #expect(response.headerFields[.connection] == "Upgrade")
        #expect(response.headerFields[.secWebSocketAccept] == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
    }

    @Test("a non-GET request is rejected (RFC 6455 §4.2.1)")
    func rejectsNonGet() {
        var request = upgradeRequest()
        request.method = .post
        #expect(throws: WebSocketHandshakeError.methodNotGet) {
            try WebSocketHandshake.response(to: request)
        }
    }

    @Test("a missing Upgrade token is rejected (§4.2.1)")
    func rejectsMissingUpgrade() {
        var fields = handshakeFields()
        fields.removeAll(named: .upgrade)
        #expect(throws: WebSocketHandshakeError.missingUpgrade) {
            try WebSocketHandshake.response(to: upgradeRequest(fields))
        }
    }

    @Test("a version other than 13 is rejected with 426 (§4.2.1 / §4.4)")
    func rejectsBadVersion() {
        var fields = handshakeFields()
        _ = fields.setValue("8", for: .secWebSocketVersion)
        #expect(throws: WebSocketHandshakeError.unsupportedVersion) {
            try WebSocketHandshake.response(to: upgradeRequest(fields))
        }
        #expect(WebSocketHandshakeError.unsupportedVersion.rejectionStatus == .upgradeRequired)
    }

    @Test("a key that is not base64 of 16 octets is rejected (§4.1)")
    func rejectsBadKey() {
        var fields = handshakeFields()
        _ = fields.setValue("too-short", for: .secWebSocketKey)
        #expect(throws: WebSocketHandshakeError.missingOrInvalidKey) {
            try WebSocketHandshake.response(to: upgradeRequest(fields))
        }
    }

    @Test("the Upgrade/Connection tokens are matched case-insensitively (RFC 9110 §5.6.1)")
    func tokensAreCaseInsensitive() throws {
        var fields = HTTPFields()
        _ = fields.append("WebSocket", for: .upgrade)
        _ = fields.append("keep-alive, Upgrade", for: .connection)  // token list
        _ = fields.append("dGhlIHNhbXBsZSBub25jZQ==", for: .secWebSocketKey)
        _ = fields.append("13", for: .secWebSocketVersion)
        let response = try WebSocketHandshake.response(to: upgradeRequest(fields))
        #expect(response.status == .switchingProtocols)
    }

    // MARK: permessage-deflate negotiation (RFC 7692 §5.1)

    @Test("a permessage-deflate offer is accepted and echoed (context-takeover, RFC 7692 §5.1)")
    func permessageDeflateOfferEchoed() throws {
        var fields = handshakeFields()
        _ = fields.append(
            "permessage-deflate; client_max_window_bits", for: .secWebSocketExtensions
        )
        let response = try WebSocketHandshake.response(to: upgradeRequest(fields))
        // No no_context_takeover offered → both directions use context-takeover; the echo omits them.
        #expect(response.headerFields[.secWebSocketExtensions] == "permessage-deflate")
        let parameters = try #require(WebSocketHandshake.negotiatePermessageDeflate(fields))
        #expect(!parameters.serverNoContextTakeover)
        #expect(!parameters.clientNoContextTakeover)
    }

    @Test("the offered no_context_takeover parameters are honored and echoed (RFC 7692 §7.1.1)")
    func permessageDeflateContextTakeoverHonored() throws {
        var fields = handshakeFields()
        _ = fields.append(
            "permessage-deflate; server_no_context_takeover; client_no_context_takeover",
            for: .secWebSocketExtensions
        )
        let response = try WebSocketHandshake.response(to: upgradeRequest(fields))
        #expect(
            response.headerFields[.secWebSocketExtensions]
                == "permessage-deflate; server_no_context_takeover; client_no_context_takeover")
        let parameters = try #require(WebSocketHandshake.negotiatePermessageDeflate(fields))
        #expect(parameters.serverNoContextTakeover)
        #expect(parameters.clientNoContextTakeover)
    }

    @Test("no permessage-deflate offer leaves the 101 without the extension (RFC 7692 §5.1)")
    func noPermessageDeflateOffer() throws {
        let response = try WebSocketHandshake.response(to: upgradeRequest())
        #expect(response.headerFields[.secWebSocketExtensions] == nil)
        #expect(WebSocketHandshake.negotiatePermessageDeflate(handshakeFields()) == nil)
    }

    @Test("an offer constraining the server window is declined (RFC 7692 §7.1.2.1)")
    func declinesServerWindowConstraint() {
        var fields = handshakeFields()
        _ = fields.append(
            "permessage-deflate; server_max_window_bits=10", for: .secWebSocketExtensions
        )
        #expect(WebSocketHandshake.negotiatePermessageDeflate(fields) == nil)
    }

    // MARK: Fixtures

    private func handshakeFields() -> HTTPFields {
        var fields = HTTPFields()
        _ = fields.append("websocket", for: .upgrade)
        _ = fields.append("Upgrade", for: .connection)
        _ = fields.append("dGhlIHNhbXBsZSBub25jZQ==", for: .secWebSocketKey)
        _ = fields.append("13", for: .secWebSocketVersion)
        return fields
    }

    private func upgradeRequest(_ fields: HTTPFields? = nil) -> HTTPRequest {
        HTTPRequest(
            method: .get,
            scheme: "https",
            authority: "example.com",
            path: "/chat",
            headerFields: fields ?? handshakeFields()
        )
    }
}
