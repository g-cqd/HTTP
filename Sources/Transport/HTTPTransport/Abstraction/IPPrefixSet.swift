//
//  IPPrefixSet.swift
//  HTTPTransport
//
//  A set of CIDR blocks, and the shape a trust boundary takes in this package: "which peers am I
//  willing to believe a forwarding header from" (RFC 7239 §8.1 — a `Forwarded` chain is only as
//  trustworthy as the hop that appended it), "which peers may reach this route at all". Membership is
//  a short linear scan of masked integer comparisons; a trust list has a handful of entries, so a scan
//  beats a data structure and allocates nothing.
//
//  ``none`` is spelled out rather than left implicit because the empty set is the safe default: trust
//  nobody, believe no forwarding header, and use the verified transport peer.
//

/// A set of CIDR blocks, tested by membership.
public struct IPPrefixSet: Hashable, Sendable, ExpressibleByArrayLiteral {
    /// The blocks, in the order they will be tested.
    public let prefixes: [IPPrefix]

    /// Trusts nobody — the safe default for a forwarding-header trust boundary.
    public static let none = Self([])

    /// The loopback blocks: `127.0.0.0/8` (RFC 1122 §3.2.1.3) and `::1/128` (RFC 4291 §2.5.3).
    public static let loopback = Self([
        IPPrefix(address: .v4(0x7f00_0000), bits: 8),
        IPPrefix(address: .v6(high: 0, low: 1), bits: 128)
    ])

    /// The blocks that are never globally routable, so a peer inside one is on the operator's own
    /// network.
    ///
    /// `10/8`, `172.16/12`, `192.168/16` (RFC 1918 §3), `100.64/10` (RFC 6598 §7), `fc00::/7`
    /// (RFC 4193 §3.1) and `fe80::/10` (RFC 4291 §2.5.6). Loopback is deliberately *not* included —
    /// combine with ``loopback`` via ``union(_:)`` when both are wanted.
    public static let privateUse = Self([
        IPPrefix(address: .v4(0x0a00_0000), bits: 8),
        IPPrefix(address: .v4(0xac10_0000), bits: 12),
        IPPrefix(address: .v4(0xc0a8_0000), bits: 16),
        IPPrefix(address: .v4(0x6440_0000), bits: 10),
        IPPrefix(address: .v6(high: 0xfc00_0000_0000_0000, low: 0), bits: 7),
        IPPrefix(address: .v6(high: 0xfe80_0000_0000_0000, low: 0), bits: 10)
    ])

    /// Creates a set from `prefixes`.
    public init(_ prefixes: [IPPrefix]) {
        self.prefixes = prefixes
    }

    /// Creates a set from an array literal of prefixes.
    public init(arrayLiteral elements: IPPrefix...) {
        self.init(elements)
    }

    /// Parses a set from CIDR strings, failing as a whole if any one of them is malformed.
    ///
    /// All-or-nothing on purpose: silently dropping an unparsable entry from a trust list would
    /// narrow or widen the boundary without saying so.
    public init?(cidrs: [String]) {
        var parsed: [IPPrefix] = []
        parsed.reserveCapacity(cidrs.count)
        for cidr in cidrs {
            guard let prefix = IPPrefix(cidr) else {
                return nil
            }
            parsed.append(prefix)
        }
        self.init(parsed)
    }

    /// Whether the set holds no blocks — and so trusts nobody.
    public var isEmpty: Bool {
        prefixes.isEmpty
    }

    /// Whether `address` falls inside any block in the set.
    public func contains(_ address: IPAddress) -> Bool {
        prefixes.contains { $0.contains(address) }
    }

    /// The set holding every block from this set and `other`.
    public func union(_ other: Self) -> Self {
        Self(prefixes + other.prefixes)
    }
}
