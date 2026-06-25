//
//  Tags.swift
//  HTTPTestSupport
//
//  Canonical test tags, so a CI lane can select or exclude a category uniformly (e.g. run only `.fuzz`
//  + `.property` under the sanitizer matrix, or exclude `.soak` from the fast lane).
//

public import Testing

extension Tag {
    /// Seeded fuzz / crash-injection suites that prove "never trap / hang / OOM".
    @Tag
    public static var fuzz: Self
    /// Property-based suites asserting an invariant over seeded random inputs.
    @Tag
    public static var property: Self
    /// Concurrency / async-coordination suites.
    @Tag
    public static var concurrency: Self
    /// Long-running soak / endurance suites.
    @Tag
    public static var soak: Self
    /// Standards-conformance suites driving RFC MUST-level vectors.
    @Tag
    public static var conformance: Self
    /// Boundary / exactness suites written to fail under a single code mutation (mutation-resistance).
    @Tag
    public static var mutation: Self
}
