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
        // h3spec contributes 49 active checks: 27 transport + 7 TLS + 11 HTTP/3 + 4 QPACK.
        #expect(checks.filter { $0.source == .h3spec }.count == 49)
        // The Swift engine implements the HTTP/3 + QPACK layers; QUIC transport/TLS are platform-enforced.
        for check in checks {
            switch check.layer {
                case .http3, .qpack:
                    #expect(check.status == .supported, "\(check.title) should be engine-supported")
                case .quicTransport, .quicTLS:
                    #expect(check.status == .platform, "\(check.title) is platform-enforced")
            }
        }
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
