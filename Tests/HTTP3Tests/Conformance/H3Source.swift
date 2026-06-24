//
//  H3Source.swift
//  HTTP3Tests
//
//  The HTTP/3 conformance catalog — a living, type-checked spec mirroring `h3spec`
//  (kazu-yamamoto/h3spec, the HTTP/3 analogue of h2spec) plus the RFC 9114 / RFC 9204 MUSTs h3spec
//  does not cover. The HTTP/3 engine is milestone M7 and is not built yet, so this is staging: every
//  engine-driven check is `.pending` and run as a disabled test (see H3SpecTests.swift). As the M7
//  engine lands, checks flip to `.supported` and their disabled tests become live drive-and-assert
//  cases — each "inject one malformation, assert the connection/stream closes with `expect`".
//
//  Tolerance (from h3spec, per RFC 9000 §11 / RFC 9114 §8): a server MAY substitute a generic
//  PROTOCOL_VIOLATION / INTERNAL_ERROR (transport) or H3_GENERAL_PROTOCOL_ERROR / H3_INTERNAL_ERROR
//  (application) for a specific code; the eventual live assertions must accept those equivalents.
//

/// Where a check originates: the h3spec tool, or an RFC MUST h3spec leaves uncovered.
enum H3Source: String, Sendable {
    case h3spec
    case rfc9000
    case rfc9001
    case rfc9114
    case rfc9204
}
