//
//  HTTPRouter.swift
//  HTTPServer
//
//  The routing seam (Phase 3.7): a responder that also resolves route metadata from a request head. The
//  server is already decoupled from the concrete ``Router`` — it drives `any HTTPResponder` and queries
//  `any RouteResolver` — so a downstream framework can swap in its own routing strategy (e.g. a typed
//  DSL) by conforming to `HTTPRouter` and passing it as the server's responder. The built-in ``Router``
//  conforms; this protocol just names the composition so the seam is discoverable.
//

/// A responder that also resolves route metadata — the pluggable routing seam (Phase 3.7).
public protocol HTTPRouter: HTTPResponder, RouteResolver {
    // A composition seam: no requirements beyond HTTPResponder + RouteResolver.
}
