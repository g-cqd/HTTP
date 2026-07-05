//
//  StructuredFields+ParserBytes.swift
//  HTTPCore
//
//  The lexical helpers behind the RFC 8941 parser: octet constants, the character-class predicates the
//  grammar is defined in terms of (DIGIT / ALPHA / key / token / base64), and number assembly with the
//  §3.3.1/§3.3.2 range and digit caps. Byte sequences (§3.3.5) decode through the shared, Foundation-free
//  ``Base64`` codec.
//

extension StructuredFields.Parser {
    static let sp = UInt8(ascii: " ")
    static let htab = UInt8(ascii: "\t")
    static let comma = UInt8(ascii: ",")
    static let equals = UInt8(ascii: "=")
    static let semicolon = UInt8(ascii: ";")
    static let openParen = UInt8(ascii: "(")
    static let closeParen = UInt8(ascii: ")")
    static let dash = UInt8(ascii: "-")
    static let dot = UInt8(ascii: ".")
    static let dquote = UInt8(ascii: "\"")
    static let backslash = UInt8(ascii: "\\")
    static let star = UInt8(ascii: "*")
    static let colon = UInt8(ascii: ":")
    static let question = UInt8(ascii: "?")
    static let one = UInt8(ascii: "1")
    static let zero = UInt8(ascii: "0")

    static func isDigit(_ byte: UInt8) -> Bool {
        byte >= zero && byte <= UInt8(ascii: "9")
    }

    static func isLCAlpha(_ byte: UInt8) -> Bool {
        byte >= UInt8(ascii: "a") && byte <= UInt8(ascii: "z")
    }

    static func isAlpha(_ byte: UInt8) -> Bool {
        isLCAlpha(byte) || (byte >= UInt8(ascii: "A") && byte <= UInt8(ascii: "Z"))
    }

    /// A key octet after the first: lowercase letter, digit, `_`, `-`, `.`, or `*` (§4.2.3.3).
    static func isKeyByte(_ byte: UInt8) -> Bool {
        isLCAlpha(byte) || isDigit(byte) || byte == UInt8(ascii: "_") || byte == dash || byte == dot
            || byte == star
    }

    /// A token octet: ALPHA / DIGIT / the tchar punctuation (RFC 9110) plus `:` and `/` (§4.2.6). The
    /// punctuation is an inlined `switch` (a jump table) rather than a `Set` — the sibling
    /// `FieldValidation.isTokenByte` measured a `Set`/lazy-`static let` form 2–3× slower per byte.
    static func isTokenByte(_ byte: UInt8) -> Bool {
        if isAlpha(byte) || isDigit(byte) { return true }
        switch byte {
            case 0x21, 0x23, 0x24, 0x25, 0x26, 0x27, 0x2A, 0x2B, 0x2D, 0x2E, 0x2F, 0x3A, 0x5E, 0x5F,
                0x60, 0x7C, 0x7E:  // ! # $ % & ' * + - . / : ^ _ ` | ~
                return true
            default:
                return false
        }
    }

    static func isBase64Byte(_ byte: UInt8) -> Bool {
        isAlpha(byte) || isDigit(byte) || byte == UInt8(ascii: "+") || byte == UInt8(ascii: "/")
            || byte == UInt8(ascii: "=")
    }

    /// Assembles the collected digits into an Integer or Decimal, enforcing the §3.3.1/§3.3.2 caps.
    static func makeNumber(
        digits: [UInt8],
        sign: Int64,
        isDecimal: Bool
    ) throws(StructuredFields.ParseError) -> StructuredFields.BareItem {
        let text = String(decoding: digits, as: Unicode.UTF8.self)
        guard isDecimal else {
            guard let magnitude = Int64(text) else {
                throw .integerOutOfRange
            }
            return .integer(sign * magnitude)
        }
        guard digits.last != dot, let dotIndex = digits.firstIndex(of: dot) else {
            throw .invalidDecimal
        }
        // §4.2.4: at most 12 digits before the decimal point (the serializer enforces the same, so the
        // codec stays symmetric — it must not accept what it cannot round-trip).
        guard dotIndex <= 12 else {
            throw .invalidDecimal
        }
        guard digits.count - dotIndex - 1 <= 3 else {
            throw .invalidDecimal
        }
        guard let magnitude = Double(text) else {
            throw .invalidDecimal
        }
        return .decimal(Double(sign) * magnitude)
    }

    /// Decodes a padded RFC 4648 §4 base64 octet string (§3.3.5), or `nil` if it is not valid base64.
    static func decodeBase64(_ input: [UInt8]) -> [UInt8]? {
        Base64.decode(input, alphabet: .standard, padded: true)
    }
}
