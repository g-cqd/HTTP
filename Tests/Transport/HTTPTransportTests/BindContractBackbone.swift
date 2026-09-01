//
//  BindContractBackbone.swift
//  HTTPTransportTests
//
//  One column of the bind-contract matrix: a listener implementation that must answer the
//  ``BindContractCase`` rows the same way as every other. Covers BOTH protocols (TCP and QUIC), BOTH
//  Network.framework generations, and the trait-gated portable TLS backbone, because "the legacy
//  path serves the floor" is exactly how a backbone gets left behind — audit F-04 fixed the modern
//  QUIC port while the legacy QUIC host was still ignored, F-05 fixed the TCP host while QUIC had
//  neither, and PortableTLS sat outside the matrix entirely until its opt-in build hid a Linux port
//  leak (and a build break) for months.
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
    /// TCP + TLS 1.3 over the portable libssl backbone — the opt-in `HTTP_PORTABLE_TLS` build, on
    /// both macOS and Linux. Every non-failing cell dials with a real TLS handshake.
    case portableTLS
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
            case .portableTLS:
                .portableTLS
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
        // Availability of the build — platform or trait — is the ONLY reason a cell may skip. There
        // used to be a second one: the POSIX backbones took `ServerTransport.boundEndpoint`'s `nil`
        // default, so their endpoint-reporting assertion was relaxed and the row recorded a skip
        // instead. All backbones report what `getsockname(2)` gives now, so the relaxation is gone
        // rather than permanent.
        _ = row
        return nil
    }

    /// Why this column cannot run at all in the build executing the suite.
    ///
    /// Availability, not preference — and on two axes. Platform: `posixEpoll` exists only where
    /// `Glibc` does, and every Network.framework column is compiled out where `Network` does not —
    /// Package.swift drops `Network/`, `POSIXKqueue/`, `SwiftSystem/`, `POSIXDispatch/*Transport` and
    /// the QUIC sources from the Linux build. Build trait: `portableTLS` exists on BOTH platforms but
    /// only in the opt-in `HTTP_PORTABLE_TLS` build, which is exactly how its defects hid — a column
    /// that is absent by default needs its absence stated, per run, in so many words. So a full
    /// picture needs the macOS job, the Linux job, AND the trait-gated legs of both, and this string
    /// is what tells a reader of one run which parts it did not see.
    var platformSkipReason: String? {
        if self == .portableTLS {
            #if canImport(CHTTPBoringSSLShims)
                return nil  // the trait is on; this column runs, on macOS and Linux alike
            #else
                return "PortableTLS is `#if canImport(CHTTPBoringSSLShims)`; this column runs only "
                    + "in the opt-in portable build (HTTP_PORTABLE_TLS=1), on both platforms"
            #endif
        }
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
