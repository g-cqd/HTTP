//
//  ResponderSnapshot.swift
//  HTTPServer
//
//  One immutable view of the hot-swappable responder (G4a): the responder itself, its ``RouteResolver``
//  face when it has one, whether it declares any WebSocket route, and the generation it belongs to.
//
//  It exists because the server serves a request in *phases* — resolve the route's body limit and
//  streaming policy from the head, read the body, then dispatch — and each phase used to reread the
//  mutex separately. A ``HTTPServer/reloadResponder(_:)`` landing between two phases therefore let one
//  request take its body policy from one table and its handler from another: an old permissive limit
//  applied to a newly restrictive route, which is precisely the combination neither generation would
//  have allowed on its own (2026-07-31 audit, finding 12). Capturing the whole view once, when the head
//  completes, makes "a request is served by exactly one generation" a property of the type rather than
//  a discipline every dispatch path has to remember.
//
//  It also moves the `as? (any RouteResolver)` downcast off the request path: an existential downcast is
//  a runtime conformance lookup, and it ran on every read of the old `currentResolver` — up to four
//  times per request. Here it runs once, when a reload mints the snapshot.
//

internal import HTTPCore

/// One generation of the server's responder, resolved once and read as a unit.
struct ResponderSnapshot: Sendable {
    /// The responder this generation dispatches to.
    let responder: any HTTPResponder

    /// The responder's ``RouteResolver`` face — a ``Router``, or a middleware chain wrapping one —
    /// or `nil` when it does not route, in which case the server stays on its global defaults.
    ///
    /// The downcast happens here, at reload time, not per read.
    let resolver: (any RouteResolver)?

    /// Whether this generation declares any WebSocket route — drives the Extended CONNECT
    /// advertisement (RFC 8441 §3 / RFC 9220), which is settled once per connection at its preface.
    let hasWebSocketRoutes: Bool

    /// A monotonic counter identifying this generation, incremented by every reload.
    ///
    /// Not read on the hot path; it exists so a test can assert that a request observed exactly one
    /// generation, which is otherwise only visible as a coincidence of limits and handlers.
    let generation: UInt64

    /// Creates the snapshot for `responder` as generation `generation`.
    init(_ responder: any HTTPResponder, generation: UInt64) {
        self.responder = responder
        let resolver = responder as? (any RouteResolver)
        self.resolver = resolver
        self.hasWebSocketRoutes = resolver?.hasWebSocketRoutes ?? false
        self.generation = generation
    }
}
