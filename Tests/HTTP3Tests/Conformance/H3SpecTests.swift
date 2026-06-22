//
//  H3SpecTests.swift
//  HTTP3Tests
//
//  The HTTP/3 conformance suite. Two checks are live today and guard the staged catalog: it must be
//  well-formed, and its error-code registries must match the RFC 9114 / RFC 9204 wire values (so the
//  constants the future engine will emit cannot silently drift). The third is the staged conformance
//  pass itself — one disabled case per catalog entry, ready to become a live drive-and-assert when the
//  M7 HTTP/3 engine lands. See H3ConformanceCatalog.swift for the catalog and the tolerance rule.
//

import Testing

@Suite("HTTP/3 conformance (h3spec + RFC 9114/9204)")
struct H3SpecTests {

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
        // No HTTP/3 engine exists yet, so every check is pending.
        #expect(checks.allSatisfy { $0.status == .pending })
    }

    @Test("the HTTP/3 and QPACK error-code registries match the RFC wire values")
    func errorCodeRegistriesMatchRFC() {
        let http3 = Dictionary(
            uniqueKeysWithValues: H3Conformance.http3ErrorCodes.map { ($0.name, $0.code) })
        #expect(http3["H3_NO_ERROR"] == 0x0100)  // RFC 9114 §8.1
        #expect(http3["H3_CLOSED_CRITICAL_STREAM"] == 0x0104)
        #expect(http3["H3_FRAME_UNEXPECTED"] == 0x0105)
        #expect(http3["H3_MISSING_SETTINGS"] == 0x010a)
        #expect(http3["H3_MESSAGE_ERROR"] == 0x010e)
        #expect(http3["H3_VERSION_FALLBACK"] == 0x0110)
        #expect(H3Conformance.http3ErrorCodes.count == 17)

        let qpack = Dictionary(
            uniqueKeysWithValues: H3Conformance.qpackErrorCodes.map { ($0.name, $0.code) })
        #expect(qpack["QPACK_DECOMPRESSION_FAILED"] == 0x0200)  // RFC 9204 §6
        #expect(qpack["QPACK_ENCODER_STREAM_ERROR"] == 0x0201)
        #expect(qpack["QPACK_DECODER_STREAM_ERROR"] == 0x0202)
        #expect(H3Conformance.qpackErrorCodes.count == 3)
    }

    // MARK: Staged conformance pass (one disabled case per catalog entry, awaiting the M7 engine)

    @Test(
        "h3spec / RFC 9114·9204 — the endpoint closes with the mandated error (staged for M7)",
        .disabled("HTTP/3 engine pending — milestone M7"),
        arguments: H3Conformance.checks)
    func endpointClosesWithMandatedError(_ check: H3Check) {
        // When the M7 HTTP/3 engine exists this becomes a live drive-and-assert: spin up an
        // HTTP3Connection, inject `check`'s malformation, and require it to close the connection or
        // stream with `check.expect` (honoring the generic-error tolerance noted in the catalog).
        // Enabling it before the engine lands fails loudly here — the intended reminder.
        Issue.record("HTTP/3 engine pending (M7) — \(check.section): \(check.title)")
    }
}
