//
//  H3Layer.swift
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

/// The protocol layer a conformance check exercises.
enum H3Layer: String, Sendable, CaseIterable {
    case quicTransport = "QUIC transport (RFC 9000)"
    case quicTLS = "QUIC-TLS (RFC 9001)"
    case http3 = "HTTP/3 (RFC 9114)"
    case qpack = "QPACK (RFC 9204)"
}
