//
//  RouteParameters.swift
//  HTTPServer
//
//  Path parameters a route pattern captured (e.g. `:id` in `/users/:id`), handed to the route handler.
//  A thin, read-only view over the captured name→value pairs.
//

/// The path parameters a matched ``Route`` captured (RFC 3986 §3.3 path segments).
public struct RouteParameters: Sendable, Equatable {
    private let values: [String: String]

    /// Creates a parameter set — empty by default, for a route with no `:name` segments.
    public init(_ values: [String: String] = [:]) {
        self.values = values
    }

    /// The captured value for `name`, or nil when the route had no such parameter.
    public subscript(_ name: String) -> String? { values[name] }
}
