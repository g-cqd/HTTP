//
//  RouteMatch.swift
//  HTTPServer
//
//  One route match, resolved once from a request head and carried to dispatch — the immutable dispatch
//  plan of the 2026-07-31 audit's findings 12 and 19.
//
//  A ``ResolvedRoute`` describes what the matched route *is* (its body limit, its WebSocket handler, its
//  streaming opt-in). It deliberately says nothing about *which* route matched or what it captured, so
//  the server could resolve metadata from the head but the router then had to find the route all over
//  again to run it. This adds the two missing halves: the captured path parameters, and a handle naming
//  the table entry — so the whole request needs exactly one walk of the table.
//
//  The handle is `nil` for a match minted by any resolver other than a ``Router`` (a downstream routing
//  strategy conforming to ``RouteResolver``), and a handle from a *different* router is ignored. Both
//  degrade to a full scan, which is the point: a stale plan must be a cache miss, never a mis-dispatch.
//

/// A route matched from a request head: its metadata, its captured parameters, and a handle back to the
/// table entry that produced it.
public struct RouteMatch: Sendable {
    /// What the matched route is — body limit, WebSocket handler, streaming opt-in.
    public var route: ResolvedRoute

    /// The path parameters this match captured (e.g. `:id` in `/users/:id`).
    ///
    /// Held as borrowed slices of the request path; a `String` is materialized only if a handler reads
    /// one, so a captured-but-unread parameter still costs no allocation (audit P6).
    public var parameters: RouteParameters

    /// Which table entry produced this match, or `nil` when no ``Router`` did.
    let handle: Handle?

    /// A back-reference to one entry of one router's table.
    struct Handle: Sendable, Hashable {
        /// The table that minted the match — checked before the index is ever used.
        let origin: RouterIdentity
        /// The index of the matching route within that table.
        let index: Int
    }

    /// Creates a match from route metadata and the parameters a pattern captured.
    ///
    /// The public initializer mints no handle, so a match from a custom ``RouteResolver`` is always
    /// re-scanned at dispatch rather than trusted as an index into someone else's table.
    public init(route: ResolvedRoute, parameters: RouteParameters = RouteParameters()) {
        self.route = route
        self.parameters = parameters
        self.handle = nil
    }

    /// Creates a match that names the table entry it came from.
    ///
    /// The ``Router``'s own path, and the only one that mints a usable handle.
    init(route: ResolvedRoute, parameters: RouteParameters, handle: Handle) {
        self.route = route
        self.parameters = parameters
        self.handle = handle
    }
}
