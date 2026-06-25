//
//  RouteGroup.swift
//  HTTPServer
//
//  A group of routes under a shared path prefix, with middleware scoped to the subtree (RFC 9110). A
//  group lowers — at build time — to its child routes, each with the prefix prepended and the group's
//  middleware wrapped outermost; nested groups compose the same way. It drops into a ``RouteBuilder``
//  block like any ``Route``. The flattening is eager, so matching stays a flat segment compare with no
//  recursion.
//

/// A path-prefixed, middleware-scoped group of routes in a ``Router`` (declared via ``RouteBuilder``).
public struct RouteGroup {
    private let segments: [Route.Segment]
    private let middleware: [any HTTPMiddleware]
    private let routes: [Route]

    /// Groups `routes` under `prefix`, scoping `middleware` (outermost first) to just those routes.
    public init(
        _ prefix: String,
        middleware: [any HTTPMiddleware] = [],
        @RouteBuilder _ routes: () -> [Route]
    ) {
        self.segments = Route.parse(prefix)
        self.middleware = middleware
        self.routes = routes()
    }

    /// The child routes, each prefixed and wrapped with the group's middleware (build-time lowering).
    var flattened: [Route] {
        routes.map { $0.prefixed(by: segments, middleware: middleware) }
    }
}

extension RouteBuilder {
    /// Lifts a ``RouteGroup`` into the route table as its flattened, prefixed child routes.
    public static func buildExpression(_ group: RouteGroup) -> [Route] {
        group.flattened
    }
}
