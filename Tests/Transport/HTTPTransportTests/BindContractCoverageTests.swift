//
//  BindContractCoverageTests.swift
//  HTTPTransportTests
//
//  The guard on the guard. `BackboneConformanceTests.bindContract` is a
//  ``BindContractBackbone`` x ``BindContractCase`` matrix, and a matrix's characteristic failure is a
//  cell that quietly stops running: in a test report a missing row and a passing row look the same.
//
//  So the grid itself is asserted here — every cell is either exercised or carries a stated reason,
//  the set of skipped cells is PINNED, and the pinned set is printed so a reader of the run log sees
//  exactly what was and was not executed. Narrowing coverage now requires editing this file, which is
//  the point.
//

import Testing

@testable import HTTPTransport

@Suite("Bind-contract coverage — the matrix cannot silently narrow")
struct BindContractCoverageTests {
    /// The full grid size, pinned so adding a backbone or a row without thinking fails here first.
    ///
    /// Eight in EVERY build configuration: the `portableTLS` column exists — and states why it is
    /// not running — even when `HTTP_PORTABLE_TLS` is off and the transport itself is compiled out.
    /// A column that vanishes with its build flag is a column nobody misses, which is how that
    /// backbone went unasserted in the first place.
    @Test("the matrix is 8 backbones x 11 rows")
    func gridIsTheExpectedSize() {
        #expect(BindContractBackbone.allCases.count == 8)
        #expect(BindContractCase.allCases.count == 11)
    }

    @Test("every cell either runs or states why it does not")
    func everyCellIsAccountedFor() {
        for backbone in BindContractBackbone.allCases {
            for row in BindContractCase.allCases {
                guard let reason = backbone.skipReason(for: row) else {
                    continue
                }
                #expect(
                    !reason.isEmpty,
                    "\(backbone.rawValue)/\(row.testDescription) is skipped with an empty reason"
                )
            }
        }
    }

    /// The skipped cells, pinned by name.
    ///
    /// Anything else skipping is a silent narrowing.
    ///
    /// Pinned per build configuration, on both axes. Platform: on macOS (no Glibc) `posixEpoll` is
    /// the platform skip and `quicModern` runs; on the Linux job the reverse holds — `posixEpoll`
    /// runs and the Network.framework columns are absent from the build entirely (Package.swift
    /// excludes `Network/` and the QUIC sources). Build trait: `portableTLS` runs on BOTH platforms
    /// when `HTTP_PORTABLE_TLS` is on and skips by name when it is off — asserted in each of the four
    /// configurations, so the pin is exact everywhere and vacuous nowhere. That is why the assertion
    /// is written against `platformSkipReason` rather than a hard-coded list.
    @Test("the skipped columns are exactly the ones this build cannot run")
    func skippedColumnsArePinned() {
        var skipped: [String] = []
        for backbone in BindContractBackbone.allCases {
            guard let reason = backbone.platformSkipReason else {
                continue
            }
            skipped.append("\(backbone.rawValue): \(reason)")
        }
        for line in skipped {
            print("BIND-CONTRACT SKIPPED COLUMN \(line)")
        }
        #if canImport(Glibc)
            #expect(BindContractBackbone.posixEpoll.platformSkipReason == nil)
            #if canImport(CHTTPBoringSSLShims)
                // Linux, portable build: epoll and portableTLS run; the six Darwin columns skip.
                #expect(
                    skipped.count == 6,
                    "expected six excluded columns on portable Linux, got \(skipped)"
                )
                #expect(BindContractBackbone.portableTLS.platformSkipReason == nil)
            #else
                // Linux, default build: only the epoll column runs.
                #expect(
                    skipped.count == 7,
                    "expected seven excluded columns on default Linux, got \(skipped)"
                )
                #expect(BindContractBackbone.portableTLS.platformSkipReason != nil)
            #endif
        #else
            #expect(BindContractBackbone.posixEpoll.platformSkipReason != nil)
            #if canImport(CHTTPBoringSSLShims)
                // macOS, portable build: every column but epoll runs, portableTLS included.
                #expect(
                    skipped.count == 1,
                    "on portable macOS only posixEpoll may skip; got \(skipped)"
                )
                #expect(BindContractBackbone.portableTLS.platformSkipReason == nil)
            #else
                // macOS, default build: epoll (platform) and portableTLS (trait) skip, nothing else.
                #expect(
                    skipped.count == 2,
                    "on default macOS only posixEpoll and portableTLS may skip; got \(skipped)"
                )
                #expect(BindContractBackbone.portableTLS.platformSkipReason != nil)
            #endif
        #endif
    }

    /// The endpoint-reporting relaxation is gone, and this is what keeps it gone.
    ///
    /// `BindContractBackbone` used to carry a `reportsBoundEndpoint` flag that was `false` for the four
    /// POSIX backbones, and the matrix recorded a named skip instead of asserting their endpoint — four
    /// of seven columns not under contract for the thing the contract is about. Every backbone reports
    /// what `getsockname(2)` gives now, so build availability (platform or trait) is the only skip
    /// reason left in the grid. Asserted rather than assumed, because "no relaxations left" is exactly
    /// the property that decays silently once the commit that removed them scrolls out of view.
    @Test("build availability is the only reason any cell skips")
    func theOnlySkipReasonIsPlatform() {
        for backbone in BindContractBackbone.allCases {
            for row in BindContractCase.allCases {
                #expect(
                    backbone.skipReason(for: row) == backbone.platformSkipReason,
                    "\(backbone.rawValue)/\(row.testDescription) skips for a non-platform reason"
                )
            }
        }
    }
}
