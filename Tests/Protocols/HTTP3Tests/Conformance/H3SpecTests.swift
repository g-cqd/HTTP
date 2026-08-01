//
//  H3SpecTests.swift
//  HTTP3Tests
//
//  The HTTP/3 conformance suite. Two guards keep the catalog honest: it must be well-formed, and its
//  error-code registries must match the RFC 9114 / RFC 9204 wire values. The third test is the live
//  conformance pass — one case per catalog entry. Each HTTP/3 (RFC 9114) and QPACK (RFC 9204) row is
//  now `.supported`: the case drives a fresh ``HTTP3Connection`` with that row's malformation and
//  asserts the engine closes the connection or resets the stream with the mandated error code (honoring
//  the generic-error tolerance from the catalog). The QUIC-transport (RFC 9000) and QUIC-TLS (RFC 9001)
//  rows are `.platform` — enforced by Apple's QUIC stack beneath the engine — so they are acknowledged,
//  not driven. The per-row injections live in H3SpecTests+Drive.swift.
//

import Testing

@testable import HTTP3

@Suite("HTTP/3 conformance (h3spec + RFC 9114/9204)")
struct H3SpecTests: HTTP3WireFixtures {
    // MARK: Live guards (the scaffold is real, not vacuous)

    @Test("the conformance catalog is well-formed")
    func catalogIsWellFormed() {
        let checks = H3Conformance.checks
        #expect(!checks.isEmpty)
        for check in checks {
            #expect(!check.section.isEmpty, "every check cites a section")
            #expect(!check.title.isEmpty, "every check describes the behavior under test")
            #expect(!check.expect.isEmpty, "every check states the expected reaction")
        }
        // h3spec contributes 49 active checks. The per-LAYER split is pinned, not just the total,
        // because it is what makes this suite the gate the external `h3spec` job cannot be (see
        // docs/standards/CONFORMANCE.md): h3spec groups its own 49 cases as 34 under
        // `describe "QUIC servers"` (27 RFC 9000 transport + 7 RFC 9001 TLS) and 15 under
        // `describe "HTTP/3 servers"` (11 RFC 9114 + 4 RFC 9204) — counted from a v0.1.13 run,
        // 2026-07-31. Those 15 are the cases that exercise code in this repository, and each must
        // appear here as an engine-driven `.supported` row. Drift in a number means the mirror
        // stopped mirroring, and the gate quietly narrowed.
        let fromH3Spec = checks.filter { $0.source == .h3spec }
        #expect(fromH3Spec.count == 49)
        let byLayer = Dictionary(grouping: fromH3Spec, by: \.layer).mapValues(\.count)
        #expect(byLayer[.quicTransport] == 27)  // h3spec "QUIC servers", RFC 9000 — excluded
        #expect(byLayer[.quicTLS] == 7)  // h3spec "QUIC servers", RFC 9001 — excluded
        #expect(byLayer[.http3] == 11)  // h3spec "HTTP/3 servers", RFC 9114 — GATED here
        #expect(byLayer[.qpack] == 4)  // h3spec "HTTP/3 servers", RFC 9204 — GATED here
        // The Swift engine implements the HTTP/3 + QPACK layers; QUIC transport/TLS are platform-enforced.
        for check in checks {
            switch check.layer {
                case .http3, .qpack:
                    #expect(check.status == .supported, "\(check.title) should be engine-supported")
                case .quicTransport, .quicTLS:
                    #expect(check.status == .platform, "\(check.title) is platform-enforced")
            }
        }
        // Nothing may sit in `.pending`. A staged row is a check that does not run, and this suite is
        // a gate: a new RFC MUST arrives `.supported` with its driver, or it does not arrive.
        #expect(checks.allSatisfy { $0.status != .pending })
    }

    @Test("the HTTP/3 and QPACK error-code registries match the RFC wire values")
    func errorCodeRegistriesMatchRFC() {
        let http3 = Dictionary(
            uniqueKeysWithValues: H3Conformance.http3ErrorCodes.map { ($0.name, $0.code) }
        )
        #expect(http3["H3_NO_ERROR"] == 0x0100)  // RFC 9114 §8.1
        #expect(http3["H3_CLOSED_CRITICAL_STREAM"] == 0x0104)
        #expect(http3["H3_FRAME_UNEXPECTED"] == 0x0105)
        #expect(http3["H3_MISSING_SETTINGS"] == 0x010a)
        #expect(http3["H3_MESSAGE_ERROR"] == 0x010e)
        #expect(http3["H3_VERSION_FALLBACK"] == 0x0110)
        #expect(H3Conformance.http3ErrorCodes.count == 17)

        let qpack = Dictionary(
            uniqueKeysWithValues: H3Conformance.qpackErrorCodes.map { ($0.name, $0.code) }
        )
        #expect(qpack["QPACK_DECOMPRESSION_FAILED"] == 0x0200)  // RFC 9204 §6
        #expect(qpack["QPACK_ENCODER_STREAM_ERROR"] == 0x0201)
        #expect(qpack["QPACK_DECODER_STREAM_ERROR"] == 0x0202)
        #expect(H3Conformance.qpackErrorCodes.count == 3)
    }

    // MARK: Live conformance pass (one case per catalog entry)

    @Test(
        "h3spec / RFC 9114·9204 — the endpoint closes with the mandated error",
        arguments: H3Conformance.checks)
    func endpointClosesWithMandatedError(_ check: H3Check) {
        switch check.status {
            case .platform:
                // RFC 9000 transport / RFC 9001 TLS — enforced by Apple's QUIC stack, not the engine.
                return
            case .pending:
                Issue.record(
                    "a catalog check is unexpectedly pending: \(check.section) \(check.title)"
                )
            case .supported:
                guard let expected = expectedWireCode(check.expect) else {
                    Issue.record("no wire code parsed from expect: \(check.expect)")
                    return
                }
                guard let observed = drive(check) else {
                    Issue.record(
                        "\(check.section) \(check.title): the engine produced no error code"
                    )
                    return
                }
                #expect(
                    isAcceptable(observed, expected: expected),
                    """
                    \(check.section) \(check.title): expected \(check.expect), \
                    got 0x\(String(observed, radix: 16))
                    """)
        }
    }
}
