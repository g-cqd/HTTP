//
//  StructuredFields+ParserBytes.swift
//  HTTPCore
//
//  The lexical helpers behind the RFC 8941 parser: octet constants, the character-class predicates the
//  grammar is defined in terms of (DIGIT / ALPHA / key / token / base64), number assembly with the
//  §3.3.1/§3.3.2 range and digit caps, and a self-contained RFC 4648 base64 decoder (HTTPCore avoids
//  Foundation, so it cannot lean on `Data(base64Encoded:)`).
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

    /// The tchar punctuation (RFC 9110) plus `:` and `/`, which a Token additionally admits (§4.2.6).
    private static let tokenPunctuation = Set("!#$%&'*+-.^_`|~:/".utf8)

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

    static func isTokenByte(_ byte: UInt8) -> Bool {
        isAlpha(byte) || isDigit(byte) || tokenPunctuation.contains(byte)
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

    /// Decodes a padded RFC 4648 base64 octet string, or `nil` if it is not valid base64.
    static func decodeBase64(_ input: [UInt8]) -> [UInt8]? {
        if input.isEmpty {
            return []
        }
        guard input.count % 4 == 0 else {
            return nil
        }
        let pad = UInt8(ascii: "=")
        var output: [UInt8] = []
        output.reserveCapacity(input.count / 4 * 3)
        var offset = 0
        while offset < input.count {
            let isLastQuantum = offset + 4 == input.count
            guard let v0 = base64Value(input[offset]),
                let v1 = base64Value(input[offset + 1])
            else {
                return nil
            }
            var quantum = (UInt32(v0) << 18) | (UInt32(v1) << 12)
            let third = input[offset + 2]
            let fourth = input[offset + 3]
            if third == pad {
                guard fourth == pad, isLastQuantum else {
                    return nil
                }
                output.append(UInt8((quantum >> 16) & 0xFF))
            }
            else {
                guard let v2 = base64Value(third) else {
                    return nil
                }
                quantum |= UInt32(v2) << 6
                if fourth == pad {
                    guard isLastQuantum else {
                        return nil
                    }
                    output.append(UInt8((quantum >> 16) & 0xFF))
                    output.append(UInt8((quantum >> 8) & 0xFF))
                }
                else {
                    guard let v3 = base64Value(fourth) else {
                        return nil
                    }
                    quantum |= UInt32(v3)
                    output.append(UInt8((quantum >> 16) & 0xFF))
                    output.append(UInt8((quantum >> 8) & 0xFF))
                    output.append(UInt8(quantum & 0xFF))
                }
            }
            offset += 4
        }
        return output
    }

    private static func base64Value(_ byte: UInt8) -> UInt8? {
        if byte >= UInt8(ascii: "A"), byte <= UInt8(ascii: "Z") {
            return byte - UInt8(ascii: "A")  // A–Z → 0–25
        }
        if byte >= UInt8(ascii: "a"), byte <= UInt8(ascii: "z") {
            return byte - UInt8(ascii: "a") + 26  // a–z → 26–51
        }
        if isDigit(byte) {
            return byte - zero + 52  // 0–9 → 52–61
        }
        if byte == UInt8(ascii: "+") {
            return 62
        }
        if byte == UInt8(ascii: "/") {
            return 63
        }
        return nil
    }
}
