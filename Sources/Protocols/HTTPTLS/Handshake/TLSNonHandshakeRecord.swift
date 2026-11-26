//
//  TLSNonHandshakeRecord.swift
//  HTTPTLS
//
//  RFC 8446 §5.1 / §6 — the role-independent verdict on an application-data or alert record:
//  the no-interleaving rule (§5.1), protected data only once connected, `close_notify` (§6.1),
//  `user_canceled` ignored, any other alert fatal (§6.2).
//

/// What a non-handshake record means for the connection (RFC 8446 §5.1 / §6).
enum TLSNonHandshakeRecord: Sendable, Equatable {
    /// Non-empty application data to surface.
    case applicationData([UInt8])
    /// Padding-only data or an ignorable alert: nothing to surface.
    case ignored
    /// The peer sent `close_notify` (§6.1).
    case peerClosed

    /// The client event this verdict surfaces, if any.
    var clientEvent: TLSClientEvent? {
        switch self {
            case .applicationData(let content):
                .applicationData(content)
            case .peerClosed:
                .peerClosed
            case .ignored:
                nil
        }
    }

    /// Classifies `event` (an `.applicationData` or `.alert` record event).
    static func classify(
        _ event: TLSRecordEvent,
        hasPartialHandshake: Bool,
        isConnected: Bool
    ) throws(TLSHandshakeError) -> Self {
        switch event {
            case .handshake:
                throw .internalError("handshake event in the non-handshake dispatch")
            case .applicationData(let content):
                guard !hasPartialHandshake else {
                    throw .interleavedHandshake(.applicationData)  // §5.1
                }
                guard isConnected else {
                    throw .record(.unexpectedProtectedRecord(.applicationData))
                }
                return content.isEmpty ? .ignored : .applicationData(content)  // empty = padding
            case .alert(let alert):
                guard !hasPartialHandshake else {
                    throw .interleavedHandshake(.alert)  // §5.1
                }
                if alert.description == .closeNotify {
                    return .peerClosed
                }
                guard alert.description == .userCanceled else {  // §6.1: user_canceled ignored
                    throw .peerAlert(alert)  // error alert — no answer owed (§6.2)
                }
                return .ignored
        }
    }
}
