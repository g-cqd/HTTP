//
//  CacheControl.swift
//  HTTPServer
//
//  RFC 9111 §5.2 — the Cache-Control directives a shared cache acts on, parsed from the field value (a
//  comma-separated list of directives, each a token or `token=value`). Only the directives the cache
//  needs are modelled; the rest are ignored. Pure stdlib, iterative, trap-free.
//
//  Every `delta-seconds` argument is clamped to 2^31 at parse time, which §1.2.2 requires: "If a cache
//  receives a delta-seconds value greater than the greatest integer it can represent, or if any of its
//  subsequent calculations overflows, the cache MUST consider the value to be 2147483648 (2^31) or the
//  greatest positive integer it can conveniently represent." Clamping here rather than at each use is
//  what keeps the *subsequent calculations* — notably `freshFor + staleWhileRevalidate` in
//  ``ResponseCache`` — provably overflow-free on values a remote client chooses.
//

/// The Cache-Control directives relevant to a shared cache (RFC 9111 §5.2).
struct CacheControl {
    var noStore = false
    var noCache = false
    var isPrivate = false
    var maxAge: Int?
    var sharedMaxAge: Int?

    /// The freshness lifetime a shared cache uses: `s-maxage` overrides `max-age` (RFC 9111 §4.2.1).
    var freshnessLifetime: Int? { sharedMaxAge ?? maxAge }

    /// Parses a `Cache-Control` field value; a nil or empty value yields no directives.
    init(_ value: String?) {
        guard let value else {
            return
        }
        for directive in value.split(separator: ",") {
            let token = Self.trimmed(directive)
            let separator = token.firstIndex(of: "=")
            let name = String(separator.map { token[..<$0] } ?? token[...]).lowercased()
            let argument = separator.map { String(Self.trimmed(token[token.index(after: $0)...])) }
            switch name {
                case "no-store":
                    noStore = true
                case "no-cache":
                    noCache = true
                case "private":
                    isPrivate = true
                case "max-age":
                    maxAge = argument.flatMap { Self.deltaSeconds($0) }
                case "s-maxage":
                    sharedMaxAge = argument.flatMap { Self.deltaSeconds($0) }
                default:
                    break
            }
        }
    }

    /// The ceiling every `delta-seconds` value is clamped to — 2^31, mandated by RFC 9111 §1.2.2.
    static let deltaSecondsCeiling = 2_147_483_648

    /// `argument` parsed as an RFC 9111 §1.2.2 `delta-seconds`, clamped to ``deltaSecondsCeiling``.
    ///
    /// Returns nil only when `argument` is not the `1*DIGIT` production at all (empty, signed, or
    /// non-numeric), which makes the directive unparseable and therefore ignored (§5.2). A value that
    /// *is* all digits but too large for `Int` is the ceiling, not nil: §1.2.2 says a cache that cannot
    /// represent the value MUST use 2^31, so `max-age=99999999999999999999` means "cache it for a very
    /// long time", never "this response has no freshness lifetime".
    static func deltaSeconds(_ argument: String) -> Int? {
        let digits = UInt8(ascii: "0") ... UInt8(ascii: "9")
        guard !argument.isEmpty, argument.utf8.allSatisfy({ digits.contains($0) }) else {
            return nil
        }
        guard let seconds = Int(argument) else {
            return deltaSecondsCeiling  // all digits, but wider than Int — §1.2.2's clamp case
        }
        return min(seconds, deltaSecondsCeiling)
    }

    /// `slice` without leading or trailing spaces or tabs (RFC 9110 OWS).
    private static func trimmed(_ slice: Substring) -> Substring {
        var slice = slice
        while let first = slice.first, first == " " || first == "\t" {
            slice = slice.dropFirst()
        }
        while let last = slice.last, last == " " || last == "\t" {
            slice = slice.dropLast()
        }
        return slice
    }
}
