//
//  Route.swift
//  HTTPServer
//
//  RFC 9110 §9 (methods) + RFC 3986 §3.3 (path) — one route: a method, a path pattern with optional
//  `:name` parameter and trailing `*` catch-all segments, and the handler to run on a match. The
//  pattern is parsed once at build time into segments so matching a request is an allocation-light
//  segment compare. A route may carry group-scoped middleware (see ``RouteGroup``), applied around its
//  handler only when present. Iterative; no recursion.
//

public import HTTPCore

/// One route in a ``Router``: a method + path pattern bound to a handler (RFC 9110 §9).
public struct Route: Sendable {
    /// A handler for a matched route: the request, the captured path parameters, and the decoded body.
    public typealias Handler =
        @Sendable (HTTPRequest, RouteParameters, [UInt8]) async -> ServerResponse

    /// A parsed path-pattern segment: a fixed component, a `:name` capture, or a trailing `*` catch-all.
    enum Segment: Sendable, Equatable {
        case literal(String)
        case parameter(String)
        case catchAll(String)
    }

    /// The method this route matches.
    public let method: HTTPMethod
    let segments: [Segment]
    let handler: Handler
    /// Middleware scoped to this route by an enclosing ``RouteGroup`` (outermost first); empty for a
    /// plain route, in which case the handler runs directly with no wrapping cost.
    let middleware: [any HTTPMiddleware]

    /// Creates a route matching `method` and `pattern`, running `handler` on a match.
    ///
    /// A `pattern` like `"/users/:id"` matches that path shape; a `:name` segment captures one path
    /// component into ``RouteParameters``, and a trailing `*` (or `*name`) captures the remaining path.
    public init(_ method: HTTPMethod, _ pattern: String, handler: @escaping Handler) {
        self.init(method, Self.parse(pattern), handler: handler, middleware: [])
    }

    /// The designated initializer — pre-parsed segments and group middleware (used by ``RouteGroup``).
    init(
        _ method: HTTPMethod,
        _ segments: [Segment],
        handler: @escaping Handler,
        middleware: [any HTTPMiddleware]
    ) {
        self.method = method
        self.segments = segments
        self.handler = handler
        self.middleware = middleware
    }

    /// Parses a path pattern into segments, dropping empty components so a leading or trailing slash
    /// does not matter (`"/a/b/"` and `"a/b"` parse alike).
    ///
    /// A `:name` is a parameter; a `*` / `*name` is a catch-all that matches the remaining path.
    static func parse(_ pattern: String) -> [Segment] {
        pattern.split(separator: "/")
            .map { component -> Segment in
                guard let first = component.first else {
                    return .literal(String(component))
                }
                switch first {
                    case ":":
                        return .parameter(String(component.dropFirst()))
                    case "*":
                        let name = component.dropFirst()
                        return .catchAll(name.isEmpty ? "*" : String(name))
                    default:
                        return .literal(String(component))
                }
            }
    }

    /// Returns the captured parameters if `components` match this route's segments, else nil.
    ///
    /// A catch-all segment matches (and captures, joined by `/`) every remaining component.
    func match(_ components: [Substring]) -> RouteParameters? {
        // Captured as borrowed `Substring` slices of the request path — no per-parameter `String` copy at
        // match time; the `String` is materialized lazily, only if the handler reads the parameter (P6).
        var captured: [String: Substring] = [:]
        var index = 0
        for segment in segments {
            switch segment {
                case .literal(let value):
                    guard index < components.count, components[index] == value else {
                        return nil
                    }
                    index += 1
                case .parameter(let name):
                    guard index < components.count else {
                        return nil
                    }
                    captured[name] = components[index]
                    index += 1
                case .catchAll(let name):
                    captured[name] = components[index...].joined(separator: "/")[...]
                    return RouteParameters(slices: captured)
            }
        }
        guard index == components.count else {
            return nil
        }
        return RouteParameters(slices: captured)
    }

    /// Runs the route's handler for `parameters`, wrapping it in this route's group middleware when any
    /// is present (a plain route calls the handler directly — no per-request wrapping cost).
    func run(
        _ request: HTTPRequest,
        _ parameters: RouteParameters,
        _ body: [UInt8]
    ) async -> ServerResponse {
        guard !middleware.isEmpty else {
            return await handler(request, parameters, body)
        }
        let handler = self.handler
        let terminal = ClosureResponder { request, body in
            await handler(request, parameters, body)
        }
        return await terminal.wrapped(by: middleware).respond(to: request, body: body)
    }

    /// A copy with `groupSegments` prepended to the path and `groupMiddleware` wrapped outermost — the
    /// build-time lowering an enclosing ``RouteGroup`` applies to each child route.
    func prefixed(
        by groupSegments: [Segment],
        middleware groupMiddleware: [any HTTPMiddleware]
    ) -> Self {
        Self(
            method,
            groupSegments + segments,
            handler: handler,
            middleware: groupMiddleware + middleware
        )
    }

    /// A `GET` route (RFC 9110 §9.3.1).
    public static func get(_ pattern: String, handler: @escaping Handler) -> Self {
        Self(.get, pattern, handler: handler)
    }

    /// A `HEAD` route (RFC 9110 §9.3.2) — usually unnecessary, as a `GET` route also answers `HEAD`.
    public static func head(_ pattern: String, handler: @escaping Handler) -> Self {
        Self(.head, pattern, handler: handler)
    }

    /// A `POST` route (RFC 9110 §9.3.3).
    public static func post(_ pattern: String, handler: @escaping Handler) -> Self {
        Self(.post, pattern, handler: handler)
    }

    /// A `PUT` route (RFC 9110 §9.3.4).
    public static func put(_ pattern: String, handler: @escaping Handler) -> Self {
        Self(.put, pattern, handler: handler)
    }

    /// A `DELETE` route (RFC 9110 §9.3.5).
    public static func delete(_ pattern: String, handler: @escaping Handler) -> Self {
        Self(.delete, pattern, handler: handler)
    }

    /// A `PATCH` route (RFC 5789).
    public static func patch(_ pattern: String, handler: @escaping Handler) -> Self {
        Self(.patch, pattern, handler: handler)
    }

    /// An `OPTIONS` route (RFC 9110 §9.3.7) — an explicit handler overrides the router's automatic
    /// `OPTIONS` response.
    public static func options(_ pattern: String, handler: @escaping Handler) -> Self {
        Self(.options, pattern, handler: handler)
    }
}
