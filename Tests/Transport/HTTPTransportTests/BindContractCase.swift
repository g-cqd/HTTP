//
//  BindContractCase.swift
//  HTTPTransportTests
//
//  One row of the bind contract — what a given ``TransportConfiguration`` host/port pair must do.
//  These are the rows of the shared matrix in `BackboneConformanceTests+BindContract.swift`; the
//  columns are ``BindContractBackbone``.
//
//  Standards: IPv4 RFC 791 / IPv6 RFC 4291 literals; the IPv4 wildcard RFC 1122 §3.2.1.3 and the IPv6
//  wildcard RFC 4291 §2.5.2; RFC 5737 §3 (TEST-NET-1, assignable to no host); RFC 2606 §2 (`.invalid`
//  resolves nowhere); ephemeral ports per RFC 6335 §6.
//

import Testing

@testable import HTTPTransport

/// A single row of the bind contract, asserted identically on every backbone.
enum BindContractCase: Sendable, CaseIterable, CustomTestStringConvertible {
    /// `host: "127.0.0.1"` — the IPv4 loopback interface, and nothing else.
    case loopbackIPv4
    /// `host: "::1"` — the IPv6 loopback interface, exercised for real rather than assumed to fall
    /// out of the IPv4 path.
    case loopbackIPv6
    /// `host: "0.0.0.0"` — every IPv4 interface (RFC 1122 §3.2.1.3).
    case wildcardIPv4
    /// `host: "::"` — every IPv6 interface (RFC 4291 §2.5.2).
    case wildcardIPv6
    /// `host: "localhost"` — a name, resolved once at `start()`.
    case hostname
    /// A non-zero port that must be bound exactly.
    case configuredPort
    /// `port: 0` — an OS-chosen port that must still be observable afterwards.
    case ephemeralPort
    /// `host: "192.0.2.1"` — RFC 5737 TEST-NET-1, which no host can be assigned.
    case nonlocalHost
    /// A name under RFC 2606 §2's `.invalid` TLD, which resolves nowhere.
    case invalidHost
    /// A second listener on a port a first one already holds.
    case portConflict
    /// Stop, then bind the same configured port again — four times in a row.
    case rebindAfterStop

    /// The configured host this row uses, or `nil` where the row is about the port.
    var host: String {
        switch self {
            case .loopbackIPv4, .configuredPort, .ephemeralPort, .portConflict, .rebindAfterStop:
                "127.0.0.1"
            case .loopbackIPv6:
                "::1"
            case .wildcardIPv4:
                "0.0.0.0"
            case .wildcardIPv6:
                "::"
            case .hostname:
                "localhost"
            case .nonlocalHost:
                "192.0.2.1"
            case .invalidHost:
                "bind-contract-target.invalid"
        }
    }

    /// Whether the row expects `start()` to throw ``TransportError``.
    var expectsBindFailure: Bool {
        switch self {
            case .nonlocalHost, .invalidHost, .portConflict:
                true
            default:
                false
        }
    }

    /// A readable name in the test log, so a matrix cell is identifiable from the report alone.
    var testDescription: String {
        switch self {
            case .loopbackIPv4:
                "loopback IPv4 127.0.0.1"
            case .loopbackIPv6:
                "loopback IPv6 ::1"
            case .wildcardIPv4:
                "wildcard IPv4 0.0.0.0"
            case .wildcardIPv6:
                "wildcard IPv6 ::"
            case .hostname:
                "hostname localhost"
            case .configuredPort:
                "configured non-zero port"
            case .ephemeralPort:
                "ephemeral port 0"
            case .nonlocalHost:
                "nonlocal host 192.0.2.1 (RFC 5737)"
            case .invalidHost:
                "invalid host .invalid (RFC 2606)"
            case .portConflict:
                "port conflict"
            case .rebindAfterStop:
                "rebind after stop"
        }
    }
}
