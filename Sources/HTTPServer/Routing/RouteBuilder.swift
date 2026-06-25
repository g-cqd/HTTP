//
//  RouteBuilder.swift
//  HTTPServer
//
//  A result builder (SE-0289) for declaring routes — `Router { Route.get("/") { … } }` — so a route
//  table reads as a flat, control-flow-friendly list. Each statement contributes a `Route` (or, from a
//  `for` / `if`, an array), flattened into the table the ``Router`` matches against.
//

/// A ``Router`` result builder: collects ``Route`` statements (and `for` / `if` groups) into a table.
@resultBuilder
public enum RouteBuilder {
    /// Lifts a single ``Route`` statement into the table.
    public static func buildExpression(_ route: Route) -> [Route] { [route] }

    /// Lifts an array of routes (e.g. returned by a helper) into the table.
    public static func buildExpression(_ routes: [Route]) -> [Route] { routes }

    /// Concatenates the statements of a builder block.
    public static func buildBlock(_ components: [Route]...) -> [Route] {
        Array(components.joined())
    }

    /// Flattens the per-iteration routes of a `for` loop.
    public static func buildArray(_ components: [[Route]]) -> [Route] { Array(components.joined()) }

    /// Yields the routes of an `if` without `else` — none when the condition is false.
    public static func buildOptional(_ component: [Route]?) -> [Route] { component ?? [] }

    /// Yields the routes of a taken `if` branch.
    public static func buildEither(first component: [Route]) -> [Route] { component }

    /// Yields the routes of a taken `else` branch.
    public static func buildEither(second component: [Route]) -> [Route] { component }
}
