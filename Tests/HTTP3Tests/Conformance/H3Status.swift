//
//  H3Status.swift
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

/// Whether the engine implements the behavior yet (drives whether the test is live or disabled).
enum H3Status: Sendable {
    case pending  // M7 not implemented — the check is staged, its test disabled
    case supported  // implemented by the Swift engine — the check runs live as a drive-and-assert
    case platform  // enforced by Apple's QUIC/TLS stack (RFC 9000/9001), not the Swift engine
}
