//
//  AcceptParsing.swift
//  HTTPCore
//
//  Shared RFC 9110 §5.6.1 comma-list + §12.4.2 q-value parsing for the proactive content-negotiation
//  `Accept*` headers (``Accept``, ``AcceptLanguage``). Lenient and trap-free — a malformed element is
//  skipped, never rejected; no Foundation.
//

/// Shared parsing for the `Accept*` content-negotiation headers (RFC 9110 §12.5).
enum AcceptParsing {
    /// Splits a field value into `(token, quality)` pairs — `token` is the range before any `;`
    /// parameters, trimmed and lowercased; empty tokens are dropped.
    static func elements(_ value: String) -> [(token: String, quality: Double)] {
        var result: [(token: String, quality: Double)] = []
        for element in value.split(separator: ",") {
            let parts = element.split(separator: ";")
            guard let first = parts.first else {
                continue
            }
            let token = trim(first).lowercased()
            guard !token.isEmpty else {
                continue
            }
            result.append((token, quality(parts.dropFirst())))
        }
        return result
    }

    /// The `q=` weight among `parameters` (RFC 9110 §12.4.2), clamped to 0...1; default 1.0 when absent.
    static func quality(_ parameters: ArraySlice<Substring>) -> Double {
        for parameter in parameters {
            let token = trim(parameter).lowercased()
            if token.hasPrefix("q="), let value = Double(token.dropFirst(2)) {
                return min(max(value, 0), 1)
            }
        }
        return 1
    }

    /// Trims ASCII spaces and tabs (RFC 9110 OWS) from both ends of `slice` — no Foundation.
    static func trim(_ slice: Substring) -> Substring {
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
