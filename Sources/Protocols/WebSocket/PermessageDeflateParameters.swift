//
//  PermessageDeflateParameters.swift
//  WebSocket
//
//  RFC 7692 §7.1 — the negotiated permessage-deflate parameters for a connection. Only the
//  context-takeover knobs are modeled: each direction either carries its LZ77 history across messages
//  (context-takeover, better compression) or resets it per message (`no_context_takeover`, bounded
//  memory). The window-bits knobs are not negotiated — this endpoint always uses a full 15-bit window
//  and declines an offer that pins the server window smaller (§7.1.2).
//

/// The permessage-deflate context-takeover parameters negotiated for a connection (RFC 7692 §7.1.1).
public struct PermessageDeflateParameters: Sendable, Equatable {
    /// Whether the server (this endpoint) resets its compressor per message (RFC 7692 §7.1.1.1).
    public var serverNoContextTakeover: Bool

    /// Whether the client resets its compressor per message, so our decompressor may too (§7.1.1.2).
    public var clientNoContextTakeover: Bool

    /// Creates the parameters; both default to context-takeover (the more compressive mode).
    public init(serverNoContextTakeover: Bool = false, clientNoContextTakeover: Bool = false) {
        self.serverNoContextTakeover = serverNoContextTakeover
        self.clientNoContextTakeover = clientNoContextTakeover
    }

    /// The `Sec-WebSocket-Extensions` value echoing these parameters in the handshake (RFC 7692 §5.1).
    public var headerValue: String {
        var value = "permessage-deflate"
        if serverNoContextTakeover { value += "; server_no_context_takeover" }
        if clientNoContextTakeover { value += "; client_no_context_takeover" }
        return value
    }
}
