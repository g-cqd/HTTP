//
//  CacheControl.swift
//  HTTPServer
//
//  RFC 9111 §5.2 — the Cache-Control directives a shared cache acts on, parsed from the field value (a
//  comma-separated list of directives, each a token or `token=value`). Only the directives the cache
//  needs are modelled; the rest are ignored. Pure stdlib, iterative, trap-free.
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
                    maxAge = argument.flatMap { Int($0) }
                case "s-maxage":
                    sharedMaxAge = argument.flatMap { Int($0) }
                default:
                    break
            }
        }
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
