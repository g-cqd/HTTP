//
//  HTTP2TunnelRefusal.swift
//  HTTPServer
//
//  Why an Extended CONNECT was denied, and the status that tells the peer so (RFC 8441 §4).
//
//  It exists to make forgetting the answer impossible rather than merely avoided. The denial paths
//  used to be four `guard … else { return }` clauses in one condition list, and a bare `return` says
//  nothing to a peer that is waiting on a stream the engine has already opened: no response, no
//  RST_STREAM, no retirement, and the slot stayed charged against `maxConcurrentStreams` (RFC 9113
//  §5.1.2) for the rest of the connection's life (2026-07-31 fifth review, R5-P0e). Making the
//  resolution RETURN a refusal instead of returning from the dispatcher means the only way to reach
//  the accept path is to have no refusal, and the only way to handle a refusal is to answer it.
//
//  RFC 8441 §5 defines a tunnel's closure entirely in stream terms — "orderly TCP-level closures are
//  represented as END_STREAM flags … RST exceptions are represented with the RST_STREAM frame" — so a
//  refusal is not a special case: it is an ordinary HTTP response on an ordinary stream. RFC 9113 §8.1
//  is the exact shape: "a server MAY request that the client abort transmission of a request without
//  error by sending a RST_STREAM with an error code of NO_ERROR after sending a complete response".
//  That is what a refused CONNECT is — a complete response for a request whose remaining bytes (the
//  tunnel's) will never be needed — and NO_ERROR is what keeps it from reading as a fault.
//

internal import HTTPCore

/// Why an Extended CONNECT was refused (RFC 8441 §4), and the status that says so.
enum HTTP2TunnelRefusal: Error, Sendable {
    /// The `:protocol` pseudo-header named something other than `websocket` (RFC 8441 §4 / RFC 9220).
    case unsupportedProtocol

    /// No route on the current responder snapshot declares a WebSocket handler for this path.
    case noRoute

    /// The route's handler declined the upgrade for this request (`shouldUpgrade`).
    case declined

    /// The request's `Origin` is not on the handler's allowlist.
    ///
    /// The cross-site WebSocket hijacking defense (RFC 6455 §10.2, CWE-1385), which the handshake is
    /// exempt from the Same-Origin Policy and CORS for. Same status as the HTTP/1.1 path uses.
    case forbiddenOrigin

    /// The status this refusal answers the peer with (RFC 9110 §15).
    var status: HTTPStatus {
        switch self {
            case .unsupportedProtocol:
                // The server does not support the functionality the request needs (§15.6.2). Not 400:
                // the request is well formed, this server simply does not tunnel that protocol.
                .notImplemented
            case .noRoute:
                .notFound  // §15.5.5 — no target resource here
            case .declined, .forbiddenOrigin:
                .forbidden  // §15.5.4 — understood, and refused
        }
    }
}
