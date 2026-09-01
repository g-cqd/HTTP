//
//  Tags.swift
//  HTTPTestSupport
//
//  Canonical test tags, so a CI lane can select or exclude a category uniformly (e.g. run only
//  `.fuzz` under the sanitizer matrix, or `.mutation` to check boundary exactness).
//
//  Every tag here labels at least one suite. `.property`, `.concurrency` and `.soak` used to sit
//  alongside them and labelled nothing: a tag no suite carries cannot select or exclude anything, so
//  it is vocabulary rather than an axis, and a lane written against one would silently run an empty
//  set. They were removed rather than kept as intent (2026-07-31 deadwood pass). Re-adding one is
//  three lines, at the moment the first suite actually needs it — which is how `.fuzz`, `.mutation`
//  and `.conformance` got here.
//

public import Testing

extension Tag {
    /// Seeded fuzz / crash-injection suites that prove "never trap / hang / OOM".
    @Tag
    public static var fuzz: Self
    /// Standards-conformance suites driving RFC MUST-level vectors.
    @Tag
    public static var conformance: Self
    /// Boundary / exactness suites written to fail under a single code mutation (mutation-resistance).
    @Tag
    public static var mutation: Self
}
