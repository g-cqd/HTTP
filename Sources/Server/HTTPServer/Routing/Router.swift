//
//  Router.swift
//  HTTPServer
//
//  RFC 9110 — a path/method ``HTTPResponder`` built from a ``RouteBuilder`` table. The first route whose
//  pattern matches the request path runs (with its captured parameters); a path match on a different
//  method is `405 Method Not Allowed` (§15.5.6) carrying an `Allow` header, an `OPTIONS` to a known path
//  with no explicit handler is answered automatically with `204` + `Allow` (§9.3.7), and no match is
//  `404 Not Found` (§15.5.5). Matching is an allocation-light segment compare over the pre-parsed
//  patterns. Iterative; no recursion.
//
//  A `Router` is just an ``HTTPResponder``, so it drops straight into `HTTPServer(responder:)` and
//  composes with middleware via ``MiddlewareChain`` (or `router.wrapped(by:)`) like any other responder.
//

public import HTTPCore

/// A path/method router (RFC 9110): declare routes with ``RouteBuilder``, serve them as an
/// ``HTTPResponder``.
public struct Router: HTTPResponder, RouteResolver {
    private let routes: [Route]

    /// Whether any route declares a WebSocket handler (RFC 6455), precomputed once — drives the Extended
    /// CONNECT advertisement (RFC 8441 / RFC 9220).
    public let hasWebSocketRoutes: Bool

    /// Builds a router from a ``RouteBuilder`` route table.
    public init(@RouteBuilder _ routes: () -> [Route]) {
        let table = routes()
        self.routes = table
        self.hasWebSocketRoutes = table.contains(where: \.isWebSocket)
    }

    /// Routes `request` to the first matching route, or an auto-`OPTIONS` / `405` / `404` (RFC 9110
    /// §9.3.7, §15.5).
    ///
    /// A `HEAD` is served by the matching `GET` route (the server omits the body, RFC 9110 §9.3.2).
    public func respond(
        to request: HTTPRequest,
        body: RequestBody,
        context: RequestContext
    ) async -> ServerResponse {
        // `OPTIONS *` is a server-wide capability query (RFC 9110 §9.3.7).
        if request.method == .options, request.path == "*" {
            return Self.allow(status: .noContent, methods: Self.serverMethods(routes))
        }
        let components = Self.pathComponents(of: request.path)
        // HEAD is GET without a body (RFC 9110 §9.3.2): match it against GET routes and let the server
        // strip the body, so a registered GET also answers HEAD instead of a spurious 405.
        let matchMethod: HTTPMethod = request.method == .head ? .get : request.method
        var pathMethods: Set<HTTPMethod> = []
        for route in routes {
            guard let parameters = route.match(components) else {
                continue
            }
            guard route.method == matchMethod else {
                pathMethods.insert(route.method)  // path matched, method did not
                continue
            }
            // Enrich the context the engine built (connection metadata, id) with this route's captures,
            // for the handler and any group middleware below it.
            var context = context
            context.parameters = parameters
            return await route.run(request, body, context)
        }
        return Self.unmatched(method: request.method, pathMethods: pathMethods)
    }

    // MARK: Route resolution (head-only)

    /// Resolves the route metadata for `method` + `path` — a head-only match that runs no handler — or
    /// `nil` when no route matches.
    public func resolve(method: HTTPMethod, path: String) -> ResolvedRoute? {
        let components = Self.pathComponents(of: path)
        // HEAD is served by the matching GET route (RFC 9110 §9.3.2), as in `respond`.
        let matchMethod: HTTPMethod = method == .head ? .get : method
        for route in routes where route.method == matchMethod {
            guard route.match(components) != nil else {
                continue
            }
            return Self.metadata(of: route)
        }
        return nil
    }

    /// Resolves the WebSocket route matching `path` (method-agnostic, for an Extended CONNECT whose
    /// `:method` is `CONNECT` while the route is declared `GET`), or `nil`.
    public func resolveWebSocket(path: String) -> ResolvedRoute? {
        let components = Self.pathComponents(of: path)
        for route in routes where route.isWebSocket {
            guard route.match(components) != nil else {
                continue
            }
            return Self.metadata(of: route)
        }
        return nil
    }

    /// The ``ResolvedRoute`` view of a matched route.
    private static func metadata(of route: Route) -> ResolvedRoute {
        ResolvedRoute(
            bodyLimit: route.bodyLimit,
            webSocketHandler: route.webSocketHandler,
            webSocketHub: route.webSocketHub,
            webSocketTopic: route.webSocketTopic,
            streamsBody: route.streamsBody
        )
    }

    /// The response when no route matched the method: an automatic `OPTIONS` (`204`), a `405` with
    /// `Allow` (RFC 9110 §15.5.6), or a `404` when the path is unknown.
    private static func unmatched(
        method: HTTPMethod,
        pathMethods: Set<HTTPMethod>
    ) -> ServerResponse {
        guard !pathMethods.isEmpty else {
            return ServerResponse(HTTPResponse(status: .notFound))
        }
        let methods = expand(pathMethods)
        return method == .options
            ? allow(status: .noContent, methods: methods)
            : allow(status: .methodNotAllowed, methods: methods)
    }

    /// A response carrying an `Allow` header listing `methods` (RFC 9110 §10.2.1).
    private static func allow(status: HTTPStatus, methods: [HTTPMethod]) -> ServerResponse {
        var head = HTTPResponse(status: status)
        _ = head.headerFields.setValue(
            methods.map(\.rawValue).joined(separator: ", "), for: .allow
        )
        return ServerResponse(head)
    }

    /// `pathMethods` plus the implicit `HEAD` (when `GET` is present) and `OPTIONS`, in a stable order.
    private static func expand(_ pathMethods: Set<HTTPMethod>) -> [HTTPMethod] {
        var methods = pathMethods
        if methods.contains(.get) { methods.insert(.head) }
        methods.insert(.options)
        return ordered(methods)
    }

    /// Every method any route serves, plus the implicit `HEAD`/`OPTIONS` — for `OPTIONS *`.
    private static func serverMethods(_ routes: [Route]) -> [HTTPMethod] {
        var methods: Set<HTTPMethod> = []
        for route in routes { methods.insert(route.method) }
        return expand(methods)
    }

    private static let methodOrder: [HTTPMethod] = [
        .get, .head, .post, .put, .patch, .delete, .options, .connect, .trace
    ]

    /// `methods` in a stable, conventional order; any custom method outside ``methodOrder`` sorts last.
    private static func ordered(_ methods: Set<HTTPMethod>) -> [HTTPMethod] {
        let known = methodOrder.filter(methods.contains)
        let extra = Array(methods)
            .filter { !methodOrder.contains($0) }
            .sorted { $0.rawValue < $1.rawValue }
        return known + extra
    }

    /// Splits a request-target path into segments, dropping the query/fragment and empty components so a
    /// trailing slash does not matter (RFC 3986 §3.3 / §3.4).
    static func pathComponents(of path: String) -> [Substring] {
        path.prefix { $0 != "?" && $0 != "#" }.split(separator: "/")
    }
}
