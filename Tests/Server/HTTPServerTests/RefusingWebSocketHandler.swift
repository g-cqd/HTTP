//
//  RefusingWebSocketHandler.swift
//  HTTPServerTests
//
//  A WebSocket handler that refuses every origin, so an Extended CONNECT is rejected *after* the engine
//  has already recorded the tunnel (RFC 9220 §3, RFC 6455 §10.2 cross-site WebSocket hijacking defense).
//
//  That window is the point: the engine marks a request stream as a tunnel the moment the CONNECT
//  HEADERS decode, and it never drops a tunnel record on its own — so a refusal that only resets the
//  wire leaves one record per rejected handshake for the life of the connection (audit R5-P0c).
//

import HTTPCore
import WebSocket

/// A handler that declines every upgrade, for driving the refused-tunnel retirement path.
struct RefusingWebSocketHandler: WebSocketHandler {
    func isOriginAllowed(_: String?) -> Bool { false }

    func handle(_: WebSocketConnection.Event) async -> [WebSocketAction] { [] }
}
