//
//  RecordingUpgradeHandler.swift
//  HTTPServerTests
//
//  A ``WebSocketHandler`` that records exactly what the *upgrade authorization* seam was handed, for
//  the R5-SEC1 regression. `shouldUpgrade(_:)` is the only place a handler ever sees the handshake
//  request's fields — `onOpen`/`handle`/`onClose` are given frames, never a request — so it is also the
//  only place a spoofed server-asserted field could reach one.
//

import HTTPCore
import Synchronization
import WebSocket

/// Records the value a named field carried when the upgrade was authorized.
struct RecordingUpgradeHandler: WebSocketHandler {
    /// The field whose value is captured on the upgrade path.
    let field: HTTPFieldName

    /// What `shouldUpgrade` saw, once it has run.
    let seen: SeenField

    func shouldUpgrade(_ request: SanitizedRequest) -> Bool {
        seen.record(request.request.headerFields[field])
        return true
    }

    /// Any origin, including none: these tests are about the ingress strip, not about CSWSH.
    func isOriginAllowed(_: String?) -> Bool { true }

    func handle(_: WebSocketConnection.Event) async -> [WebSocketAction] { [] }
}
