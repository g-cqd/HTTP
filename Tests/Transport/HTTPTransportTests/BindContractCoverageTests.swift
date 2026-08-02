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
    @Test("the matrix is 7 backbones x 11 rows")
    func gridIsTheExpectedSize() {
        #expect(BindContractBackbone.allCases.count == 7)
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
    /// On this host (macOS 26+, no Glibc) the only whole-column skip is `posixEpoll`; `quicModern`
    /// runs. On the Linux job the reverse holds — `posixEpoll` runs and both Network.framework
    /// columns are absent from the build entirely (Package.swift excludes `Network/` and the QUIC
    /// sources), which is why the assertion below is written against `platformSkipReason` rather than
    /// a hard-coded list.
    @Test("the skipped columns are exactly the ones this platform cannot build")
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
            // Linux builds only the epoll column; the other six are excluded from the package there.
            #expect(skipped.count == 6, "expected six excluded columns on Linux, got \(skipped)")
            #expect(BindContractBackbone.posixEpoll.platformSkipReason == nil)
        #else
            // macOS builds every column but epoll, which needs Glibc.
            #expect(
                skipped.count == 1,
                "on macOS only posixEpoll may skip for platform reasons; got \(skipped)"
            )
            #expect(BindContractBackbone.posixEpoll.platformSkipReason != nil)
        #endif
    }

    /// The endpoint-reporting relaxation is gone, and this is what keeps it gone.
    ///
    /// `BindContractBackbone` used to carry a `reportsBoundEndpoint` flag that was `false` for the four
    /// POSIX backbones, and the matrix recorded a named skip instead of asserting their endpoint — four
    /// of seven columns not under contract for the thing the contract is about. All four report what
    /// `getsockname(2)` gives now, so platform availability is the only skip reason left in the grid.
    /// Asserted rather than assumed, because "no relaxations left" is exactly the property that decays
    /// silently once the commit that removed them scrolls out of view.
    @Test("platform availability is the only reason any cell skips")
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
