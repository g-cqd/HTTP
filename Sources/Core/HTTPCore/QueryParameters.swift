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
        let source = Array(slice.utf8)
        var output: [UInt8] = []
        output.reserveCapacity(source.count)
        var index = 0
        while index < source.count {
            let byte = source[index]
            if byte == UInt8(ascii: "+") {
                output.append(UInt8(ascii: " "))
                index += 1
            }
            else if byte == UInt8(ascii: "%"), index + 2 < source.count,
                let high = hexValue(source[index + 1]), let low = hexValue(source[index + 2])
            {
                output.append(high << 4 | low)
                index += 3
            }
            else {
                output.append(byte)
                index += 1
            }
        }
        return String(decoding: output, as: Unicode.UTF8.self)
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
