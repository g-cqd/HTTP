//
//  StructuredFieldsStackTests.swift
//  HTTPCoreTests
//
//  RFC 8941 — the Structured Fields parser is written iteratively ("no recursion: an inner list nests
//  exactly one level", StructuredFields.swift). This locks that claim against a future regression to a
//  recursive descent: each parser is run over adversarially large inputs on a deliberately tiny
//  (512 KiB) thread stack via ``DepthSweep`` / ``runOnConstrainedStack``, where one stack frame per
//  member would SIGBUS long before returning. Reaching the end of the sweep is the assertion — a
//  recursive rewrite would crash the process here instead of passing silently on the main test stack.
//

import HTTPCore
import HTTPTestSupport
import Testing

@Suite("RFC 8941 — Structured Fields parsing stays iterative (bounded stack)", .tags(.fuzz))
struct StructuredFieldsStackTests {
    /// A flat list of `count` bare tokens: `a, a, …, a`.
    private static func tokenList(_ count: Int) -> String {
        Array(repeating: "a", count: count).joined(separator: ", ")
    }

    /// A single inner list of `count` bare tokens: `(a a … a)`.
    private static func innerList(_ count: Int) -> String {
        "(" + Array(repeating: "a", count: count).joined(separator: " ") + ")"
    }

    @Test("a list with very many members parses without growing the stack")
    func longListParsesIteratively() {
        DepthSweep.around(upTo: 50_000)
            .run { depth in
                _ = try? StructuredFields.parseList(Self.tokenList(depth))
            }
    }

    @Test("an inner list with very many members parses without growing the stack")
    func longInnerListParsesIteratively() {
        DepthSweep.around(upTo: 50_000)
            .run { depth in
                _ = try? StructuredFields.parseList(Self.innerList(depth))
            }
    }
}
