//
//  Route.swift
//  HTTPServer
//
//  RFC 9110 §9 (methods) + RFC 3986 §3.3 (path) — one route: a method, a path pattern with optional
//  `:name` parameter segments, and the handler to run on a match. The pattern is parsed once at build
//  time into segments so matching a request is an allocation-light segment compare. Iterative; no
//  recursion.
//

public import HTTPCore

/// One route in a ``Router``: a method + path pattern bound to a handler (RFC 9110 §9).
public struct Route: Sendable {
    /// A handler for a matched route: the request, the captured path parameters, and the decoded body.
    public typealias Handler =
        @Sendable (HTTPRequest, RouteParameters, [UInt8]) async -> ServerResponse

    /// A parsed path-pattern segment: a fixed component or a `:name` capture.
    enum Segment: Sendable, Equatable {
        case literal(String)
        case parameter(String)
    }

    /// The method this route matches.
    public let method: HTTPMethod
    let segments: [Segment]
    let handler: Handler

    /// Creates a route matching `method` and `pattern`, running `handler` on a match.
    ///
    /// A `pattern` like `"/users/:id"` matches that path shape; a `:name` segment captures the
    /// corresponding path component into ``RouteParameters``.
    public init(_ method: HTTPMethod, _ pattern: String, handler: @escaping Handler) {
        self.method = method
        self.segments = Self.parse(pattern)
        self.handler = handler
    }

    /// Parses a path pattern into segments, dropping empty components so a leading or trailing slash
    /// does not matter (`"/a/b/"` and `"a/b"` parse alike).
    static func parse(_ pattern: String) -> [Segment] {
        pattern.split(separator: "/")
            .map { component in
                component.first == ":"
                    ? .parameter(String(component.dropFirst()))
                    : .literal(String(component))
            }
    }

    /// Returns the captured parameters if `components` match this route's segments, else nil.
    func match(_ components: [Substring]) -> RouteParameters? {
        guard components.count == segments.count else {
            return nil
        }
        var captured: [String: String] = [:]
        for (segment, component) in zip(segments, components) {
            switch segment {
                case .literal(let value):
                    guard component == value else {
                        return nil
                    }
                case .parameter(let name):
                    captured[name] = String(component)
            }
        }
        return RouteParameters(captured)
    }

    /// A `GET` route (RFC 9110 §9.3.1).
    public static func get(_ pattern: String, handler: @escaping Handler) -> Self {
        Self(.get, pattern, handler: handler)
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
}
