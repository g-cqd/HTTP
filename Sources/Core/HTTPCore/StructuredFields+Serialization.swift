//
//  StructuredFields+Serialization.swift
//  HTTPCore
//
//  RFC 8941 §4.1 — serialize a value back to its canonical field-value string. The inverse of the
//  parser: it validates that each value the model holds is representable on the wire (integer range,
//  decimal digits, string / token / key grammar) and fails with a typed ``StructuredFields/
//  SerializeError`` otherwise. Grammar predicates are reused from the parser so there is one source of
//  truth for what each production admits. Byte sequences (§4.1.3) encode through the shared ``Base64``.
//

extension StructuredFields {
    /// Serializes an Item to its canonical field value (RFC 8941 §4.1.3).
    public static func serialize(_ item: Item) throws(SerializeError) -> String {
        try serializeItem(item)
    }

    /// Serializes a List to its canonical field value (RFC 8941 §4.1.1).
    public static func serialize(list members: [Member]) throws(SerializeError) -> String {
        var parts: [String] = []
        for member in members {
            parts.append(try serializeMember(member))
        }
        return parts.joined(separator: ", ")
    }

    /// Serializes a Dictionary to its canonical field value (RFC 8941 §4.1.2).
    public static func serialize(
        dictionary entries: [DictionaryEntry]
    ) throws(SerializeError) -> String {
        var parts: [String] = []
        for entry in entries {
            let key = try serializeKey(entry.key)
            if case .item(let item) = entry.value, case .boolean(true) = item.bareItem {
                parts.append("\(key)\(try serializeParameters(item.parameters))")  // bare key form
            }
            else {
                parts.append("\(key)=\(try serializeMember(entry.value))")
            }
        }
        return parts.joined(separator: ", ")
    }

    // MARK: Members

    private static func serializeMember(_ member: Member) throws(SerializeError) -> String {
        switch member {
            case .item(let item):
                return try serializeItem(item)
            case .innerList(let list):
                return try serializeInnerList(list)
        }
    }

    private static func serializeItem(_ item: Item) throws(SerializeError) -> String {
        let bare = try serializeBareItem(item.bareItem)
        return bare + (try serializeParameters(item.parameters))
    }

    private static func serializeInnerList(_ list: InnerList) throws(SerializeError) -> String {
        var parts: [String] = []
        for item in list.items {
            parts.append(try serializeItem(item))
        }
        let body = parts.joined(separator: " ")
        return "(\(body))\(try serializeParameters(list.parameters))"
    }

    private static func serializeParameters(
        _ parameters: Parameters
    ) throws(SerializeError) -> String {
        var output = ""
        for parameter in parameters.entries {
            output += ";\(try serializeKey(parameter.key))"
            if case .boolean(true) = parameter.value {
                continue  // a true-valued parameter is the bare key
            }
            output += "=\(try serializeBareItem(parameter.value))"
        }
        return output
    }

    // MARK: Bare items

    private static func serializeBareItem(_ item: BareItem) throws(SerializeError) -> String {
        switch item {
            case .integer(let value):
                return try serializeInteger(value)
            case .decimal(let value):
                return try serializeDecimal(value)
            case .string(let value):
                return try serializeString(value)
            case .token(let value):
                return try serializeToken(value)
            case .byteSequence(let value):
                return ":\(base64Encode(value)):"
            case .boolean(let value):
                return value ? "?1" : "?0"
        }
    }

    private static func serializeInteger(_ value: Int64) throws(SerializeError) -> String {
        guard value >= -999_999_999_999_999, value <= 999_999_999_999_999 else {
            throw .integerOutOfRange
        }
        return String(value)
    }

    private static func serializeString(_ string: String) throws(SerializeError) -> String {
        var output = "\""
        for byte in string.utf8 {
            guard byte >= 0x20, byte < 0x7F else {
                throw .invalidStringCharacter
            }
            if byte == Parser.dquote || byte == Parser.backslash {
                output.append("\\")
            }
            output.unicodeScalars.append(Unicode.Scalar(byte))
        }
        output.append("\"")
        return output
    }

    private static func serializeToken(_ token: String) throws(SerializeError) -> String {
        // Validate over the borrowed `UTF8View` directly — no `Array(token.utf8)` copy just to scan.
        let utf8 = token.utf8
        guard let first = utf8.first, Parser.isAlpha(first) || first == Parser.star else {
            throw .invalidToken
        }
        for byte in utf8 where !Parser.isTokenByte(byte) {
            throw .invalidToken
        }
        return token
    }

    private static func serializeKey(_ key: String) throws(SerializeError) -> String {
        // Validate over the borrowed `UTF8View` directly — no `Array(key.utf8)` copy just to scan.
        let utf8 = key.utf8
        guard let first = utf8.first, Parser.isLCAlpha(first) || first == Parser.star else {
            throw .invalidKey
        }
        for byte in utf8 where !Parser.isKeyByte(byte) {
            throw .invalidKey
        }
        return key
    }

    private static func serializeDecimal(_ value: Double) throws(SerializeError) -> String {
        guard value.isFinite else {
            throw .invalidDecimal
        }
        // scale to thousandths, rounding ties to even (RFC 8941 §4.1.3.2)
        let scaled = (value * 1_000).rounded(.toNearestOrEven)
        guard scaled.magnitude < 9.0e18 else {  // stays within Int64 before conversion
            throw .invalidDecimal
        }
        let thousandths = Int64(scaled)
        let magnitude = thousandths.magnitude
        let integerPart = magnitude / 1_000
        // ≤ 12 integer digits (RFC 8941 §4.1.3.2) ⇔ < 10¹² — counted arithmetically, no `String` alloc.
        guard integerPart < 1_000_000_000_000 else {
            throw .invalidDecimal
        }
        var fraction = String(magnitude % 1_000)
        fraction = String(repeating: "0", count: 3 - fraction.count) + fraction
        while fraction.count > 1, fraction.hasSuffix("0") {
            fraction.removeLast()  // trim trailing zeros, keeping at least one fractional digit
        }
        let sign = thousandths < 0 ? "-" : ""
        return "\(sign)\(integerPart).\(fraction)"
    }

    private static func base64Encode(_ bytes: [UInt8]) -> String {
        Base64.encode(bytes, alphabet: .standard, padded: true)
    }
}
