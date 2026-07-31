//
//  IPAddress.swift
//  HTTPTransport
//
//  A parsed IP literal (RFC 791 §3.1, RFC 4291 §2.2) — the value ``TransportAddress`` only ever had as
//  an unparsed `host` string. A server that wants to key anything on "who is calling" needs a numeric
//  address it can mask, compare against a prefix, and use as a map key; a string cannot do any of
//  those, and comparing strings would let `010.0.0.1`, `10.0.0.1` and `::ffff:10.0.0.1` denote three
//  different clients while addressing the same host.
//
//  Parsing is deliberately strict and literal-only — no DNS, no host names, no resolution of any kind
//  (this runs on the request path). It rejects leading zeros in a dotted quad, because a permissive
//  parser reads `0177.0.0.1` as octal 127.0.0.1 while a strict one reads it as invalid, and an
//  allow/deny check that disagrees with the socket about which host it is looking at is a bypass
//  (CVE-2021-29662, CVE-2021-28918, CWE-1289). It rejects a zone identifier (RFC 4007 §11) for the
//  same reason, and it folds the IPv4-mapped form `::ffff:a.b.c.d` onto ``v4`` (RFC 4291 §2.5.5.2) so
//  a client cannot obtain two budgets by switching representation.
//

/// An IPv4 or IPv6 address, stored numerically.
public enum IPAddress: Hashable, Sendable {
    /// An IPv4 address as a 32-bit value in host byte order (RFC 791 §3.1).
    case v4(UInt32)

    /// An IPv6 address as two 64-bit halves, most significant first (RFC 4291 §2.2).
    case v6(high: UInt64, low: UInt64)

    /// A 128-bit value carried as two halves while parsing or shifting.
    private typealias Bits = (high: UInt64, low: UInt64)

    /// Accumulates the 16-bit groups either side of an RFC 4291 §2.2 `::`.
    ///
    /// Groups before the `::` are collected right-aligned and shifted to the top at the end; groups
    /// after it are already in their final low-order position, so the two halves simply OR together.
    private struct GroupAccumulator {
        var head: Bits = (high: 0, low: 0)
        var tail: Bits = (high: 0, low: 0)
        var headCount = 0
        var tailCount = 0
        var compressed = false
        /// Whether a trailing dotted quad has been consumed; nothing may follow it.
        var embeddedIPv4 = false

        /// Appends one group, or reports that a ninth group was offered.
        mutating func append(_ group: UInt16) -> Bool {
            guard headCount + tailCount < 8 else {
                return false
            }
            if compressed {
                tail = Self.appending(group, to: tail)
                tailCount += 1
            }
            else {
                head = Self.appending(group, to: head)
                headCount += 1
            }
            return true
        }

        /// The assembled address, or `nil` when the group count is not a legal RFC 4291 §2.2 form.
        var address: IPAddress? {
            // A `::` stands for *one or more* zero groups, so a compressed form holds at most 7.
            guard compressed ? headCount + tailCount <= 7 : headCount == 8 else {
                return nil
            }
            let shifted = Self.shiftedLeft(head, by: 128 - 16 * headCount)
            return .v6(high: shifted.high | tail.high, low: shifted.low | tail.low)
        }

        /// `value` shifted left 16 bits with `group` appended in the low bits.
        private static func appending(_ group: UInt16, to value: Bits) -> Bits {
            (high: (value.high << 16) | (value.low >> 48), low: (value.low << 16) | UInt64(group))
        }

        /// `value` shifted left by `bits`, across the 64-bit boundary.
        private static func shiftedLeft(_ value: Bits, by bits: Int) -> Bits {
            guard bits > 0 else {
                return value
            }
            guard bits < 64 else {
                return (high: bits < 128 ? value.low << (bits - 64) : 0, low: 0)
            }
            return (high: (value.high << bits) | (value.low >> (64 - bits)), low: value.low << bits)
        }
    }

    /// The number of bits a prefix over this address family may cover: 32 for IPv4, 128 for IPv6.
    public var bitWidth: UInt8 {
        switch self {
            case .v4:
                32
            case .v6:
                128
        }
    }

    /// This address with everything below the top `bits` cleared — the network prefix.
    ///
    /// A rate limiter aggregates IPv6 clients this way: a single subscriber is routinely handed a
    /// whole /64 (RFC 6177 §2), so a per-address budget is evaded by walking the subnet.
    public func masked(to bits: UInt8) -> Self {
        switch self {
            case .v4(let value):
                guard bits < 32 else {
                    return self
                }
                return .v4(value & (~UInt32(0) << (32 - UInt32(bits))))
            case .v6(let high, let low):
                guard bits < 128 else {
                    return self
                }
                let keepHigh = min(Int(bits), 64)
                let keepLow = max(Int(bits) - 64, 0)
                return .v6(
                    high: high & Self.leadingMask(keepHigh),
                    low: low & Self.leadingMask(keepLow)
                )
        }
    }

    /// The address in its canonical textual form — a dotted quad, or RFC 5952 §4 for IPv6.
    ///
    /// One deterministic spelling per address, because this is a map key: lower-case hex, no leading
    /// zeros in a group, and the longest run of two or more zero groups compressed to `::` (leftmost
    /// on a tie). Short enough for the common cases — every IPv4 address, and any IPv6 prefix — to be
    /// a Swift small string, so keying on it costs no allocation.
    public var canonicalText: String {
        switch self {
            case .v4(let value):
                let octets = (value >> 24, (value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff)
                return "\(octets.0).\(octets.1).\(octets.2).\(octets.3)"
            case .v6(let high, let low):
                return Self.canonicalIPv6Text(high: high, low: low)
        }
    }

    /// Parses an IP literal, or fails.
    ///
    /// Accepts a dotted quad, an RFC 4291 §2.2 IPv6 form (including the trailing dotted-quad and the
    /// bracketed `[…]` spellings), and nothing else — no host name is resolved and no zone identifier
    /// is accepted. `::ffff:a.b.c.d` folds onto ``v4`` (RFC 4291 §2.5.5.2).
    public init?(_ text: some StringProtocol) {
        guard let parsed = Self.parse(text.utf8) else {
            return nil
        }
        self = parsed
    }

    /// A mask keeping the top `bits` of a 64-bit half.
    private static func leadingMask(_ bits: Int) -> UInt64 {
        bits <= 0 ? 0 : ~UInt64(0) << (64 - min(bits, 64))
    }

    /// The 16-bit group at `index`, most significant first (RFC 4291 §2.2).
    private static func group(_ index: Int, high: UInt64, low: UInt64) -> UInt16 {
        let word = index < 4 ? high : low
        return UInt16(truncatingIfNeeded: word >> UInt64(48 - 16 * (index % 4)))
    }

    /// The longest run of two or more zero groups, leftmost on a tie (RFC 5952 §4.2.3).
    private static func longestZeroRun(high: UInt64, low: UInt64) -> (start: Int, length: Int) {
        var best = (start: -1, length: 0)
        var runStart = -1
        for index in 0 ..< 8 {
            guard group(index, high: high, low: low) == 0 else {
                runStart = -1
                continue
            }
            if runStart < 0 {
                runStart = index
            }
            let length = index - runStart + 1
            if length > best.length {
                best = (start: runStart, length: length)
            }
        }
        return best.length >= 2 ? best : (start: -1, length: 0)
    }

    /// The RFC 5952 §4 canonical text of a 128-bit address.
    private static func canonicalIPv6Text(high: UInt64, low: UInt64) -> String {
        let run = longestZeroRun(high: high, low: low)
        var text = ""
        text.reserveCapacity(39)
        var index = 0
        while index < 8 {
            guard index != run.start else {
                text += "::"
                index += run.length
                continue
            }
            if index > 0, text.last != ":" {
                text += ":"
            }
            text += String(group(index, high: high, low: low), radix: 16)
            index += 1
        }
        return text.isEmpty ? "::" : text
    }

    /// Strips one bracketed wrapper, rejects a zone identifier, and dispatches on the family.
    private static func parse(_ utf8: some Collection<UInt8>) -> Self? {
        var start = utf8.startIndex
        var end = utf8.endIndex
        guard start != end else {
            return nil
        }
        if utf8[start] == UInt8(ascii: "[") {
            start = utf8.index(after: start)
            guard let closing = utf8[start ..< end].firstIndex(of: UInt8(ascii: "]")),
                utf8.index(after: closing) == end
            else {
                return nil
            }
            end = closing
        }
        let body = utf8[start ..< end]
        // 45 = the longest legal literal, "0000:…:0000:255.255.255.255"; anything longer is hostile.
        guard !body.isEmpty, body.count <= 45, !body.contains(UInt8(ascii: "%")) else {
            return nil
        }
        guard body.contains(UInt8(ascii: ":")) else {
            return parseIPv4(body).map { .v4($0) }
        }
        return parseIPv6(body)
    }

    /// Parses a strict dotted quad: four decimal octets, no leading zeros, nothing else.
    private static func parseIPv4(_ utf8: some Collection<UInt8>) -> UInt32? {
        var packed: UInt32 = 0
        var dots = 0
        var octet = 0
        var digits = 0
        for byte in utf8 {
            guard byte != UInt8(ascii: ".") else {
                guard digits > 0, dots < 3 else {
                    return nil
                }
                packed = (packed << 8) | UInt32(octet)
                (dots, octet, digits) = (dots + 1, 0, 0)
                continue
            }
            // `digits == 0 || octet != 0` rejects a leading zero, which an octal-aware parser
            // elsewhere in the stack would read as a different address entirely (CWE-1289).
            guard let digit = decimalDigit(byte), digits < 3, digits == 0 || octet != 0 else {
                return nil
            }
            octet = octet * 10 + digit
            digits += 1
            guard octet <= 255 else {
                return nil
            }
        }
        guard digits > 0, dots == 3 else {
            return nil
        }
        return (packed << 8) | UInt32(octet)
    }

    /// Parses an RFC 4291 §2.2 IPv6 literal, folding the IPv4-mapped form onto ``v4``.
    private static func parseIPv6(_ utf8: some Collection<UInt8>) -> Self? {
        var accumulator = GroupAccumulator()
        var index = utf8.startIndex
        let end = utf8.endIndex
        if utf8[index] == UInt8(ascii: ":") {
            index = utf8.index(after: index)
            guard index != end, utf8[index] == UInt8(ascii: ":") else {
                return nil  // a single leading colon is not a legal form
            }
            index = utf8.index(after: index)
            accumulator.compressed = true
        }
        while index != end {
            let tokenEnd = utf8[index ..< end].firstIndex(of: UInt8(ascii: ":")) ?? end
            // RFC 4291 §2.2 form 3: the dotted quad, if present, is the *last* token.
            guard !accumulator.embeddedIPv4,
                append(utf8[index ..< tokenEnd], to: &accumulator)
            else {
                return nil
            }
            index = tokenEnd
            guard index != end else {
                break
            }
            index = utf8.index(after: index)
            guard index != end else {
                return nil  // a trailing single colon is not a legal form
            }
            guard utf8[index] != UInt8(ascii: ":") else {
                guard !accumulator.compressed else {
                    return nil  // at most one `::`
                }
                accumulator.compressed = true
                index = utf8.index(after: index)
                continue
            }
        }
        return accumulator.address.map { $0.foldingIPv4Mapped() }
    }

    /// Appends one token — a hex group, or a trailing dotted quad worth two groups.
    private static func append(
        _ token: some Collection<UInt8>,
        to accumulator: inout GroupAccumulator
    ) -> Bool {
        guard !token.isEmpty else {
            return false
        }
        if token.contains(UInt8(ascii: ".")) {
            guard let packed = parseIPv4(token) else {
                return false
            }
            accumulator.embeddedIPv4 = true
            return accumulator.append(UInt16(truncatingIfNeeded: packed >> 16))
                && accumulator.append(UInt16(truncatingIfNeeded: packed))
        }
        guard token.count <= 4 else {
            return false
        }
        var group: UInt16 = 0
        for byte in token {
            guard let digit = hexDigit(byte) else {
                return false
            }
            group = (group << 4) | UInt16(digit)
        }
        return accumulator.append(group)
    }

    /// `::ffff:a.b.c.d` as ``v4`` (RFC 4291 §2.5.5.2), so one host never has two identities.
    private func foldingIPv4Mapped() -> Self {
        guard case .v6(let high, let low) = self, high == 0, low >> 32 == 0xffff else {
            return self
        }
        return .v4(UInt32(truncatingIfNeeded: low))
    }

    /// The value of an ASCII decimal digit, or `nil`.
    private static func decimalDigit(_ byte: UInt8) -> Int? {
        (0x30 ... 0x39).contains(byte) ? Int(byte - 0x30) : nil
    }

    /// The value of an ASCII hex digit in either case, or `nil`.
    private static func hexDigit(_ byte: UInt8) -> Int? {
        switch byte {
            case 0x30 ... 0x39:
                Int(byte - 0x30)
            case 0x61 ... 0x66:
                Int(byte - 0x61) + 10
            case 0x41 ... 0x46:
                Int(byte - 0x41) + 10
            default:
                nil
        }
    }
}
