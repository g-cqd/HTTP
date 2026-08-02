//
//  BindContractBackbone.swift
//  HTTPTransportTests
//
//  One column of the bind-contract matrix: a listener implementation that must answer the
//  ``BindContractCase`` rows the same way as every other. Covers BOTH protocols (TCP and QUIC) and
//  BOTH Network.framework generations, because "the legacy path serves the floor" is exactly how a
//  backbone gets left behind — audit F-04 fixed the modern QUIC port while the legacy QUIC host was
//  still ignored, and F-05 fixed the TCP host while QUIC had neither.
//
//  A column that cannot run a row says so by name through ``skipReason(for:)``. A missing row and a
//  passing row read identically in a test report, which is the failure mode this file exists to avoid.
//

import Testing

@testable import HTTPTransport

/// A listener implementation under the bind contract.
enum BindContractBackbone: String, Sendable, CaseIterable, CustomTestStringConvertible {
    /// TCP over Network.framework (`NWListener`), the TLS/ALPN backbone.
    case networkFramework
    /// TCP over BSD sockets with a hand-rolled kqueue readiness loop.
    case posixKqueue
    /// TCP over BSD sockets with GCD `DispatchSource` readiness.
    case posixDispatch
    /// TCP over apple/swift-system typed `FileDescriptor`s on the shared kqueue loop.
    case swiftSystem
    /// TCP over BSD sockets with an `epoll(7)` readiness loop — Linux only.
    case posixEpoll
    /// QUIC over the legacy `NWListener` + `NWConnectionGroup` path (macOS 15.6 / iOS 18 floor).
    case quicLegacy
    /// QUIC over the modern typed `NetworkListener<QUIC>` path (macOS 26+).
    case quicModern

    /// Whether this column speaks QUIC (UDP, RFC 9000) rather than TCP (RFC 9293).
    var isQUIC: Bool {
        self == .quicLegacy || self == .quicModern
    }

    /// The `TransportBackbone` a TCP column instantiates, or `nil` for the QUIC columns.
    var transportBackbone: TransportBackbone? {
        switch self {
            case .networkFramework:
                .networkFramework
            case .posixKqueue:
                .posixKqueue
            case .posixDispatch:
                .posixDispatch
            case .swiftSystem:
                .swiftSystem
            case .posixEpoll:
                .posixEpoll
            case .quicLegacy, .quicModern:
                nil
        }
    }

    /// Why this column cannot run `row`, or `nil` when it runs it.
    ///
    /// Every non-`nil` answer names a concrete, checkable reason. `BindContractCoverageTests` asserts
    /// the whole grid is accounted for, so a cell can never quietly vanish.
    func skipReason(for row: BindContractCase) -> String? {
        if let platform = platformSkipReason {
            return platform
        }
        // Platform availability is the ONLY reason a cell may skip. There used to be a second one — the
        // POSIX backbones took `ServerTransport.boundEndpoint`'s `nil` default, so their
        // endpoint-reporting assertion was relaxed and the row recorded a skip instead. All four report
        // what `getsockname(2)` gives now, so the relaxation is gone rather than permanent.
        _ = row
        return nil
    }

    /// Why this column cannot run at all on the host executing the suite.
    ///
    /// Platform, not preference. The two sets are disjoint and complementary: `posixEpoll` exists
    /// only where `Glibc` does, and every other column is compiled out where `Network` does not —
    /// Package.swift drops `Network/`, `POSIXKqueue/`, `SwiftSystem/`, `POSIXDispatch/*Transport` and
    /// the QUIC sources from the Linux build. So a full picture needs BOTH jobs, and this string is
    /// what tells a reader of one run which half it did not see.
    var platformSkipReason: String? {
        #if canImport(Glibc)
            switch self {
                case .posixEpoll:
                    return nil
                default:
                    return "\(rawValue) is excluded from the Linux build (Package.swift); this "
                        + "column runs on the macOS job"
            }
        #else
            switch self {
                case .posixEpoll:
                    return "POSIXEpoll is `#if canImport(Glibc)`; this column runs only on the "
                        + "Linux job (scripts/linux-test.sh test)"
                case .quicModern:
                    guard #available(macOS 26, iOS 26, *) else {
                        return "ModernQUICTransport is @available(macOS 26, iOS 26); this host is "
                            + "below that floor and the legacy column covers it"
                    }
                    return nil
                default:
                    return nil
            }
        #endif
    }

    var testDescription: String {
        rawValue
    }
}
