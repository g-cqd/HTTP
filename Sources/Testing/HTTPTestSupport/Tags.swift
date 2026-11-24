//
//  Tags.swift
//  HTTPTestSupport
//
//  HTTP-specific test tags complementing `AemiTestKit`'s canonical tags (`.fuzz`, `.parity`,
//  `.property`, `.soak`, `.concurrency`, `.bench`).
//

public import Testing

extension Tag {
    /// Standards-conformance suites driving RFC MUST-level vectors.
    @Tag
    public static var conformance: Self
    /// Mutation-testing suites proving every boundary check is exercised.
    @Tag
    public static var mutation: Self
}
