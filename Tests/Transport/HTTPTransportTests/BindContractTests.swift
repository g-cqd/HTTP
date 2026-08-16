//
//  BindContractTests.swift
//  HTTPTransportTests
//
//  ONE matrix: ``BindContractBackbone`` columns x ``BindContractCase`` rows, so what
//  ``TransportConfiguration``'s `host` and `port` mean is asserted identically on every listener the
//  package ships — TCP and QUIC, legacy Network.framework and modern, POSIX and not.
//
//  Written as a matrix rather than a pile of near-duplicate functions because the defect class is
//  DRIFT, not any single bug. Audit F-04 (modern QUIC ignored the port) and F-05 (Network.framework
//  ignored the host) are the same defect seen from two backbones, and each was invisible from the
//  other's tests. A per-backbone suite reproduces exactly that blindness.
//
//  Every cell either runs or is skipped BY NAME through ``BindContractBackbone/skipReason(for:)`` and
//  ``BindContractBackbone/platformSkipReason``; `BindContractCoverageTests` asserts the whole grid is
//  accounted for, because a missing row and a passing row read identically in a report.
//
//  Reading `boundPort` back is never the assertion. F-04 was a listener that bound one port and
//  reported another, so each non-failing row DIALS the endpoint the listener claims — a real
//  `connect(2)` + echo for TCP, a real QUIC handshake (RFC 9000, ALPN `h3` per RFC 7301) for QUIC.
//
//  Standards: TCP RFC 9293, QUIC RFC 9000 over UDP RFC 768; IPv4 RFC 791 / IPv6 RFC 4291 literals;
//  wildcards RFC 1122 §3.2.1.3 and RFC 4291 §2.5.2; RFC 5737 §3 and RFC 2606 §2 for the unbindable
//  rows; CWE-668 (exposure to an unintended actor), CWE-755 (unhandled exceptional condition).
//

import HTTPTestSupport
import Testing

@testable import HTTPTransport

#if canImport(Darwin)
    internal import Darwin
#elseif canImport(Glibc)
    internal import Glibc
#endif

@Suite("Bind contract — every backbone, the same table", .realNetwork)
struct BindContractTests {
    // `.serialized` because every cell binds a real listener and dials it: eighty-eight of those at
    // once saturates the shared real-network permit pool and pushes unrelated suites past their time
    // limits. Serially the whole matrix is a few seconds, and the ordering is reproducible.
    @Test(
        "the bind contract holds on every backbone",
        .serialized,
        .timeLimit(.minutes(1)),
        arguments: BindContractBackbone.allCases, BindContractCase.allCases)
    func bindContract(
        _ backbone: BindContractBackbone, _ row: BindContractCase
    ) async throws {
        if let reason = backbone.skipReason(for: row) {
            Self.recordSkip(backbone, row, reason)
            return
        }
        switch row {
            case .portConflict:
                try await Self.assertPortConflictFailsClosed(backbone)
            case .rebindAfterStop:
                try await Self.assertRebindAfterStop(backbone)
            case .nonlocalHost, .invalidHost:
                await Self.assertBindFailsClosed(backbone, host: row.host)
            case .configuredPort:
                try await Self.assertBinds(
                    backbone, row, host: row.host, port: Self.freePort(backbone)
                )
            default:
                try await Self.assertBinds(backbone, row, host: row.host, port: 0)
        }
    }

    // MARK: - Row bodies

    /// Binds `host`/`port`, then proves the listener is REACHABLE at the endpoint it reports.
    private static func assertBinds(
        _ backbone: BindContractBackbone, _ row: BindContractCase, host: String, port: UInt16
    ) async throws {
        let resolved = try BindEndpoint.resolve(host: host, port: port)
        let subject = try await BindContractSubject.start(backbone, host: host, port: port)
        defer { Task { await subject.stop() } }

        let realized = subject.boundPort()
        #expect(realized != 0, "\(backbone.rawValue) reported no bound port for host \(host)")
        if port != 0 {
            #expect(realized == port, "\(backbone.rawValue) bound \(realized), configured \(port)")
        }

        // Asserted on every column, with no per-backbone relaxation left: the POSIX backbones used to
        // take `ServerTransport`'s `nil` default here and the row recorded a skip instead, which meant
        // four of the seven columns were not actually under contract for the thing the contract is about.
        let reported = try #require(
            subject.boundEndpoint(),
            "\(backbone.rawValue) reported no bound endpoint after binding \(host)"
        )
        #expect(reported.address == resolved.address)
        #expect(reported.family == resolved.family)
        #expect(reported.port == realized)
        #expect(reported.isWildcard == resolved.isWildcard)
        _ = row

        // A wildcard is reachable through the loopback of its own family; an interface pin is
        // reachable at the literal it pinned. Either way the PORT under test is the reported one.
        let target = BindEndpoint(
            address: resolved.isWildcard ? loopbackLiteral(of: resolved.family) : resolved.address,
            family: resolved.family,
            port: realized
        )
        #expect(
            await subject.dial(target),
            "\(backbone.rawValue) reported \(target.description) but no client arrived there"
        )
    }

    /// A host that cannot be bound must throw ``TransportError``, not start somewhere else.
    private static func assertBindFailsClosed(
        _ backbone: BindContractBackbone, host: String
    ) async {
        await #expect(throws: TransportError.self) {
            let subject = try await BindContractSubject.start(backbone, host: host, port: 0)
            await subject.stop()
        }
    }

    /// A second listener on a held port must throw rather than silently share it.
    private static func assertPortConflictFailsClosed(
        _ backbone: BindContractBackbone
    ) async throws {
        let holder = try await BindContractSubject.start(backbone, host: "127.0.0.1", port: 0)
        let held = holder.boundPort()
        #expect(held != 0)
        await #expect(throws: TransportError.self) {
            let clashing = try await BindContractSubject.start(
                backbone, host: "127.0.0.1", port: held
            )
            await clashing.stop()
        }
        await holder.stop()
    }

    /// Four stop/start cycles on one configured port: each stop must actually release it.
    private static func assertRebindAfterStop(_ backbone: BindContractBackbone) async throws {
        try await rebindCycles(backbone, port: freePort(backbone))
    }

    private static func rebindCycles(_ backbone: BindContractBackbone, port: UInt16) async throws {
        for cycle in 0 ..< 4 {
            let subject = try await BindContractSubject.start(
                backbone, host: "127.0.0.1", port: port
            )
            #expect(
                subject.boundPort() == port,
                "\(backbone.rawValue) cycle \(cycle) bound \(subject.boundPort()), not \(port)"
            )
            await subject.stop()
        }
    }

    // MARK: - Helpers

    /// A free loopback port of the right transport for `backbone` (UDP for QUIC, TCP otherwise).
    static func freePort(_ backbone: BindContractBackbone) throws -> UInt16 {
        try BindContractSubject.unusedPort(
            backbone.isQUIC
                ? BindContractSubject.datagramSocketType : BindContractSubject.streamSocketType
        )
    }

    /// The loopback literal of `family` — where a wildcard-bound listener is reachable.
    static func loopbackLiteral(of family: BindEndpoint.Family) -> String {
        switch family {
            case .ipv4:
                "127.0.0.1"
            case .ipv6:
                "::1"
        }
    }

    /// Records a skipped cell so it appears in the report as a stated reason, never as silence.
    ///
    /// Swift Testing has no per-argument skip, so the line goes to the run log in a greppable shape
    /// and `BindContractCoverageTests` asserts the whole grid — every cell either runs or carries a
    /// reason, and the set of skipped cells is pinned. A cell cannot go quiet without failing that.
    static func recordSkip(
        _ backbone: BindContractBackbone, _ row: BindContractCase, _ reason: String
    ) {
        print("BIND-CONTRACT SKIP \(backbone.rawValue) / \(row.testDescription): \(reason)")
    }
}
