//
//  Cookies.swift
//  HTTPCore
//
//  RFC 6265bis — HTTP state management. `Cookies.parse` reads the `Cookie` request header into
//  name→value pairs (§4.2). Iterative; no Foundation.
//

/// Parses the `Cookie` request header (RFC 6265bis §4.2).
public enum Cookies {
    /// The cookies in `fields` as name→value pairs (RFC 6265bis §4.2.1); later duplicates win.
    public static func parse(_ fields: HTTPFields) -> [String: String] {
        var cookies: [String: String] = [:]
        for header in fields.values(for: .cookie) {
            for pair in header.split(separator: ";") {
                guard let separator = pair.firstIndex(of: "=") else { continue }
                let name = trimmed(pair[..<separator])
                let value = trimmed(pair[pair.index(after: separator)...])
                if !name.isEmpty { cookies[String(name)] = String(value) }
            }
        }
        return cookies
    }

    /// `slice` without leading or trailing spaces or tabs (RFC 9110 OWS).
    private static func trimmed(_ slice: Substring) -> Substring {
        var slice = slice
        while let first = slice.first, first == " " || first == "\t" { slice = slice.dropFirst() }
        while let last = slice.last, last == " " || last == "\t" { slice = slice.dropLast() }
        return slice
    }
}
