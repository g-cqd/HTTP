//
//  IPPrefix.swift
//  HTTPTransport
//
//  A CIDR block (RFC 4632 §3.1 for IPv4, RFC 4291 §2.3 for IPv6): an ``IPAddress`` plus the number of
//  leading bits that are significant. It is the unit a server states trust in — "these are my reverse
//  proxies", "this is my private network" — and membership is a masked comparison of two integers, so
//  a check costs no allocation and no string work on the request path.
//
//  The address is masked to `bits` at construction, so `10.1.2.3/8` and `10.0.0.0/8` are the same
//  value and `contains(_:)` never has to normalize. Two prefixes of different families never contain
//  each other's addresses: the masked comparison is on the enum, so the family is part of the answer.
//

/// A CIDR block: a network address and the number of significant leading bits.
public struct IPPrefix: Hashable, Sendable {
    /// The network address, already masked to ``bits``.
    public let address: IPAddress

    /// The number of significant leading bits (0…32 for IPv4, 0…128 for IPv6).
    public let bits: UInt8

    /// Creates a prefix, clamping `bits` to the family width and masking off the host bits.
    public init(address: IPAddress, bits: UInt8) {
        let clamped = min(bits, address.bitWidth)
        self.address = address.masked(to: clamped)
        self.bits = clamped
    }

    /// Parses `address/bits` — `"10.0.0.0/8"`, `"::1/128"` — or fails.
    ///
    /// A prefix length wider than the family (`"10.0.0.0/33"`) is rejected rather than clamped: it
    /// almost certainly means the configuration says something other than its author intended, and a
    /// trust list that silently widens is the wrong thing to guess at.
    public init?(_ cidr: some StringProtocol) {
        guard let separator = cidr.lastIndex(of: "/"),
            let address = IPAddress(cidr[cidr.startIndex ..< separator])
        else {
            return nil
        }
        // One spelling per length: decimal, no sign, no leading zero — for the same reason the
        // address parser rejects `010.0.0.1` (CWE-1289, one text must mean one thing).
        let digits = cidr[cidr.index(after: separator)...]
        guard !digits.isEmpty, digits.count <= 3,
            digits.count == 1 || digits.first != "0",
            digits.utf8.allSatisfy({ (0x30 ... 0x39).contains($0) }),
            let bits = UInt8(digits), bits <= address.bitWidth
        else {
            return nil
        }
        self.init(address: address, bits: bits)
    }

    /// Whether `address` falls inside this block.
    public func contains(_ address: IPAddress) -> Bool {
        address.masked(to: bits) == self.address
    }
}
