//
//  StructuredFields+Serialization.swift
//  HTTPCore
//
//  RFC 8941 §4.1 — serialize a value back to its canonical field-value string. The inverse of the
//  parser: it validates that each value the model holds is representable on the wire (integer range,
//  decimal digits, string / token / key grammar) and fails with a typed ``StructuredFields/
//  SerializeError`` otherwise. Grammar predicates are reused from the parser so there is one source of
//  truth for what each production admits. Includes a self-contained RFC 4648 base64 encoder.
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
        let bytes = Array(token.utf8)
        guard let first = bytes.first, Parser.isAlpha(first) || first == Parser.star else {
            throw .invalidToken
        }
        for byte in bytes where !Parser.isTokenByte(byte) {
            throw .invalidToken
        }
        return token
    }

    private static func serializeKey(_ key: String) throws(SerializeError) -> String {
        let bytes = Array(key.utf8)
        guard let first = bytes.first, Parser.isLCAlpha(first) || first == Parser.star else {
            throw .invalidKey
        }
        for byte in bytes where !Parser.isKeyByte(byte) {
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
        guard String(integerPart).count <= 12 else {
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
        let alphabet = Array(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".utf8
        )
        let pad = UInt8(ascii: "=")
        var output: [UInt8] = []
        output.reserveCapacity((bytes.count + 2) / 3 * 4)
        var offset = 0
        while offset + 3 <= bytes.count {
            let chunk =
                (UInt32(bytes[offset]) << 16) | (UInt32(bytes[offset + 1]) << 8)
                | UInt32(bytes[offset + 2])
            output.append(alphabet[Int((chunk >> 18) & 0x3F)])
            output.append(alphabet[Int((chunk >> 12) & 0x3F)])
            output.append(alphabet[Int((chunk >> 6) & 0x3F)])
            output.append(alphabet[Int(chunk & 0x3F)])
            offset += 3
        }
        let remaining = bytes.count - offset
        if remaining == 1 {
            let chunk = UInt32(bytes[offset]) << 16
            output.append(alphabet[Int((chunk >> 18) & 0x3F)])
            output.append(alphabet[Int((chunk >> 12) & 0x3F)])
            output.append(pad)
            output.append(pad)
        }
        else if remaining == 2 {
            let chunk = (UInt32(bytes[offset]) << 16) | (UInt32(bytes[offset + 1]) << 8)
            output.append(alphabet[Int((chunk >> 18) & 0x3F)])
            output.append(alphabet[Int((chunk >> 12) & 0x3F)])
            output.append(alphabet[Int((chunk >> 6) & 0x3F)])
            output.append(pad)
        }
        return String(decoding: output, as: Unicode.UTF8.self)
    }
}
