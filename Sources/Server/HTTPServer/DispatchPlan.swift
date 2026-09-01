//
//  DispatchPlan.swift
//  HTTPServer
//
//  Everything the server decides about a request from its head, decided once: which generation of the
//  hot-swappable responder is serving it (``ResponderSnapshot``), and which route it matched
//  (``RouteMatch`` — the handler handle, the captured parameters, the body limit, the streaming
//  opt-in, the WebSocket metadata).
//
//  The two belong to one value because they are only meaningful together. A ``RouteMatch`` names an
//  entry in *some* router's table; carrying it without the generation that produced it would let a hot
//  reload land between head and dispatch and pair one generation's body limit with another's handler
//  (2026-07-31 audit, finding 12) — the match would simply be rejected by the new table's identity
//  check and silently re-scanned, which is safe but is exactly the split the finding describes.
//  Carrying them together makes "one request, one generation, one table walk" a single fact.
//
//  HTTP/1.1 holds the plan as a local for the length of one exchange. HTTP/2 and HTTP/3 cannot: their
//  heads resolve on one task and dispatch on another, an arbitrary interval later, so the plan is filed
//  per stream (``HTTP2DispatchPlans``, ``HTTP3StreamRegistry``) and taken again at dispatch.
//

/// The immutable plan for serving one request: its responder generation and the route it matched.
struct DispatchPlan: Sendable {
    /// The generation serving this request — its responder, and the table its match came from.
    let snapshot: ResponderSnapshot

    /// The route this request's head matched, or `nil` when no route did (or the responder does not
    /// route at all), in which case the server stays on its global defaults.
    var match: RouteMatch?

    /// This route's body ceiling, or `nil` for the global ``HTTPLimits/maxBodySize``.
    var bodyLimit: Int? { match?.route.bodyLimit }

    /// Whether this route consumes its request body incrementally (Phase 1.4).
    var streamsBody: Bool { match?.route.streamsBody ?? false }

    /// Creates a plan for `snapshot`, optionally carrying the route its head already matched.
    init(snapshot: ResponderSnapshot, match: RouteMatch? = nil) {
        self.snapshot = snapshot
        self.match = match
    }
}
