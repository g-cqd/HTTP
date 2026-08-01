//
//  CountingWebSocketHandler.swift
//  HTTPServerTests
//
//  A ``WebSocketHandler`` decorator that counts `onClose` calls, for the exactly-once lifecycle
//  guarantee (RFC 6455 §7). A peer RST_STREAM on an HTTP/2 tunnel must fire it exactly once, and
//  neither zero times (the pump never learned) nor twice (two teardown paths both ran).
//

import HTTPCore
import Synchronization
import WebSocket

/// Wraps a handler to count its `onClose` calls.
struct CountingWebSocketHandler: WebSocketHandler {
    let base: any WebSocketHandler
    let counter: CloseCounter
    let report: @Sendable () -> Void

    func shouldUpgrade(_ request: SanitizedRequest) -> Bool { base.shouldUpgrade(request) }

    func isOriginAllowed(_ origin: String?) -> Bool { base.isOriginAllowed(origin) }

    func onOpen() async -> [WebSocketAction] { await base.onOpen() }

    func handle(_ event: WebSocketConnection.Event) async -> [WebSocketAction] {
        await base.handle(event)
    }

    func onClose() async {
        await base.onClose()
        counter.bump()
        report()
    }
}
