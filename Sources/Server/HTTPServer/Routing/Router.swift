//
//  Router.swift
//  HTTPServer
//
//  RFC 9110 — a path/method ``HTTPResponder`` built from a ``RouteBuilder`` table. The first route whose
//  pattern matches the request path runs (with its captured parameters); a path match on a different
//  method is `405 Method Not Allowed` (§15.5.6), and no match is `404 Not Found` (§15.5.5). Matching is
//  an allocation-light segment compare over the pre-parsed patterns. Iterative; no recursion.
//
//  A `Router` is just an ``HTTPResponder``, so it drops straight into `HTTPServer(responder:)` and
//  composes with middleware via ``MiddlewareChain`` (or `router.wrapped(by:)`) like any other responder.
//

public import HTTPCore

/// A path/method router (RFC 9110): declare routes with ``RouteBuilder``, serve them as an
/// ``HTTPResponder``.
public struct Router: HTTPResponder {
    private let routes: [Route]

    /// Builds a router from a ``RouteBuilder`` route table.
    public init(@RouteBuilder _ routes: () -> [Route]) {
        self.routes = routes()
    }

    /// Routes `request` to the first matching route, or a `404` / `405` (RFC 9110 §15.5).
    ///
    /// A `HEAD` is served by the matching `GET` route (the server omits the body, RFC 9110 §9.3.2).
    public func respond(to request: HTTPRequest, body: [UInt8]) async -> ServerResponse {
        let components = Self.pathComponents(of: request.path)
        // HEAD is GET without a body (RFC 9110 §9.3.2): match it against GET routes and let the server
        // strip the body, so a registered GET also answers HEAD instead of a spurious 405.
        let matchMethod: HTTPMethod = request.method == .head ? .get : request.method
        var methodMismatch = false
        for route in routes {
            guard let parameters = route.match(components) else {
                continue
            }
            guard route.method == matchMethod else {
                methodMismatch = true  // path matched, method did not — remember for a 405
                continue
            }
            return await route.handler(request, parameters, body)
        }
        return ServerResponse(HTTPResponse(status: methodMismatch ? .methodNotAllowed : .notFound))
    }

    /// Splits a request-target path into segments, dropping the query/fragment and empty components so a
    /// trailing slash does not matter (RFC 3986 §3.3 / §3.4).
    static func pathComponents(of path: String) -> [Substring] {
        path.prefix { $0 != "?" && $0 != "#" }.split(separator: "/")
    }
}
