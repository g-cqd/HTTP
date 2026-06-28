//
//  RouteParameters.swift
//  HTTPServer
//
//  Path parameters a route pattern captured (e.g. `:id` in `/users/:id`, or a `*path` catch-all), handed
//  to the route handler. A thin, read-only view over the captured name→value pairs, with dynamic-member
//  access (`parameters.id`) alongside the subscript.
//

/// The path parameters a matched ``Route`` captured (RFC 3986 §3.3 path segments).
@dynamicMemberLookup
public struct RouteParameters: Sendable, Equatable {
    /// Captured values held as borrowed `Substring` slices of the request path; a `String` is
    /// materialized only when a handler actually reads the parameter (audit P6), so a captured-but-unread
    /// parameter costs no allocation.
    private let values: [String: Substring]

    /// Creates a parameter set from the matcher's captured path slices.
    init(slices values: [String: Substring]) {
        self.values = values
    }

    /// Creates a parameter set — empty by default, for a route with no `:name`/`*` segments.
    public init(_ values: [String: String] = [:]) {
        self.values = values.mapValues { $0[...] }
    }

    /// The captured value for `name`, or nil when the route had no such parameter.
    public subscript(_ name: String) -> String? { values[name].map(String.init) }

    /// Dynamic-member access: `parameters.id` is `parameters["id"]`.
    public subscript(dynamicMember name: String) -> String? { values[name].map(String.init) }
}
