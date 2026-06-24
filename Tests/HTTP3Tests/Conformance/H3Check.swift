//
//  H3Check.swift
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

/// One HTTP/3 conformance check: the malformation to inject and the error the endpoint must answer with.
struct H3Check: Sendable {
    let source: H3Source
    let layer: H3Layer
    /// The RFC section (and h3spec tag where applicable).
    let section: String
    /// The behavior under test (verbatim from h3spec where it is the source).
    let title: String
    /// The expected endpoint reaction — the error code (with its wire value for HTTP/3 / QPACK codes).
    let expect: String
    var status: H3Status

    init(
        _ source: H3Source,
        _ layer: H3Layer,
        _ section: String,
        _ title: String,
        _ expect: String,
        status: H3Status = .pending
    ) {
        self.source = source
        self.layer = layer
        self.section = section
        self.title = title
        self.expect = expect
        self.status = status
    }
}
