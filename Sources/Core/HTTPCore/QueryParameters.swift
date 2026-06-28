//
//  QueryParameters.swift
//  HTTPCore
//
//  RFC 3986 §3.4 — the query component of a request target, parsed into name→value pairs with
//  percent-decoding (and `+` → space, the `application/x-www-form-urlencoded` convention). Parsing is
//  lenient and trap-free: a malformed `%XX` escape is left literal rather than rejected, so an
//  attacker-controlled query never crashes the parser. Iterative; no Foundation.
//

/// The query parameters of a request target (RFC 3986 §3.4), as decoded name→value pairs.
@dynamicMemberLookup
public struct QueryParameters: Sendable, Equatable {
    private let values: [String: String]

    /// Creates a parameter set — empty by default.
    public init(_ values: [String: String] = [:]) {
        self.values = values
    }

    /// The decoded value for `name`, or nil when the query had no such parameter.
    ///
    /// A valueless flag (`?debug`) reads as an empty string.
    public subscript(_ name: String) -> String? { values[name] }

    /// Dynamic-member access: `query.page` is `query["page"]`.
    public subscript(dynamicMember name: String) -> String? { values[name] }

    /// Parses the query component of `target` (the part after `?`, up to any `#`) into decoded pairs.
    ///
    /// Later duplicates win; returns an empty set when there is no query.
    public static func parse(_ target: String) -> Self {
        guard let mark = target.firstIndex(of: "?") else {
            return Self()
        }
        var query = target[target.index(after: mark)...]
        if let fragment = query.firstIndex(of: "#") {
            query = query[..<fragment]
        }
        var values: [String: String] = [:]
        for pair in query.split(separator: "&", omittingEmptySubsequences: true) {
            if let separator = pair.firstIndex(of: "=") {
                let name = percentDecoded(pair[..<separator])
                guard !name.isEmpty else { continue }
                values[name] = percentDecoded(pair[pair.index(after: separator)...])
            }
            else {
                let name = percentDecoded(pair)
                if !name.isEmpty { values[name] = "" }
            }
        }
        return Self(values)
    }

    /// Percent-decodes `slice` (RFC 3986 §2.1), mapping `+` to space; a malformed `%XX` stays literal.
    private static func percentDecoded(_ slice: Substring) -> String {
        let utf8 = slice.utf8
        // Fast path (audit F10): with neither a `%` escape nor a `+`, the value is the slice verbatim, so
        // return it directly and skip the decode buffer. Most query values are unescaped (common case).
        if !utf8.contains(where: { $0 == UInt8(ascii: "%") || $0 == UInt8(ascii: "+") }) {
            return String(slice)
        }
        // Decode straight off the borrowed `UTF8View` — no `Array(slice.utf8)` copy of the whole value.
        var output: [UInt8] = []
        output.reserveCapacity(utf8.count)
        var index = utf8.startIndex
        let end = utf8.endIndex
        while index < end {
            let byte = utf8[index]
            if byte == UInt8(ascii: "+") {
                output.append(UInt8(ascii: " "))
                index = utf8.index(after: index)
            }
            else if byte == UInt8(ascii: "%"),
                let escape = decodeEscape(utf8, after: index, end: end)
            {
                output.append(escape.byte)
                index = escape.next
            }
            else {
                output.append(byte)
                index = utf8.index(after: index)
            }
        }
        return String(decoding: output, as: Unicode.UTF8.self)
    }

    /// Decodes the `%XX` escape that begins at `percent`, returning the byte and the index just past it,
    /// or nil when the two hex digits are not both present (the `%` is then left literal).
    private static func decodeEscape(
        _ utf8: Substring.UTF8View,
        after percent: Substring.UTF8View.Index,
        end: Substring.UTF8View.Index
    ) -> (byte: UInt8, next: Substring.UTF8View.Index)? {
        let high = utf8.index(after: percent)
        guard high < end else {
            return nil
        }
        let low = utf8.index(after: high)
        guard low < end, let hi = hexValue(utf8[high]), let lo = hexValue(utf8[low]) else {
            return nil
        }
        return (hi << 4 | lo, utf8.index(after: low))
    }

    /// The value of a single hex digit, or nil if `byte` is not `[0-9A-Fa-f]`.
    private static func hexValue(_ byte: UInt8) -> UInt8? {
        switch byte {
            case UInt8(ascii: "0") ... UInt8(ascii: "9"):
                return byte - UInt8(ascii: "0")
            case UInt8(ascii: "A") ... UInt8(ascii: "F"):
                return byte - UInt8(ascii: "A") + 10
            case UInt8(ascii: "a") ... UInt8(ascii: "f"):
                return byte - UInt8(ascii: "a") + 10
            default:
                return nil
        }
    }
}

extension HTTPRequest {
    /// The decoded query parameters of the request target (RFC 3986 §3.4).
    public var query: QueryParameters { QueryParameters.parse(path) }

    /// The cookies sent with the request, as name→value pairs (RFC 6265bis §4.2).
    public var cookies: [String: String] { Cookies.parse(headerFields) }
}
