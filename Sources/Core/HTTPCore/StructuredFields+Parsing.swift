//
//  StructuredFields+Parsing.swift
//  HTTPCore
//
//  RFC 8941 §4.2 — the fail-closed parser for the three top-level field types (List, Dictionary,
//  Item). It runs over the field value's ASCII octets through a bounded cursor: every step either
//  consumes input or stops, so it cannot loop forever, and it never traps — malformed input is a typed
//  ``StructuredFields/ParseError``. There is no recursion: an inner list nests exactly one level and
//  contains only items (RFC 8941 §3.1.1), so it is parsed inline.
//

extension StructuredFields {
    /// Parses a single Item field value (RFC 8941 §4.2, field type "item").
    public static func parseItem(_ source: String) throws(ParseError) -> Item {
        var source = source
        let outcome: Result<Item, ParseError> = source.withUTF8 { buffer in
            Result { () throws(ParseError) in
                var parser = Parser(ByteReader(UnsafeRawBufferPointer(buffer)))
                parser.skipSP()
                guard !parser.isAtEnd else {
                    throw .empty
                }
                let item = try parser.parseItem()
                parser.skipSP()
                guard parser.isAtEnd else {
                    throw .trailingCharacters
                }
                return item
            }
        }
        return try outcome.get()
    }

    /// Parses a List field value (RFC 8941 §4.2, field type "list"); an empty value is an empty list.
    public static func parseList(_ source: String) throws(ParseError) -> [Member] {
        var source = source
        let outcome: Result<[Member], ParseError> = source.withUTF8 { buffer in
            Result { () throws(ParseError) in
                var parser = Parser(ByteReader(UnsafeRawBufferPointer(buffer)))
                parser.skipSP()
                let members = try parser.parseListMembers()
                parser.skipSP()
                guard parser.isAtEnd else {
                    throw .trailingCharacters
                }
                return members
            }
        }
        return try outcome.get()
    }

    /// Parses a Dictionary field value (RFC 8941 §4.2, field type "dictionary"); empty → empty.
    public static func parseDictionary(_ source: String) throws(ParseError) -> [DictionaryEntry] {
        var source = source
        let outcome: Result<[DictionaryEntry], ParseError> = source.withUTF8 { buffer in
            Result { () throws(ParseError) in
                var parser = Parser(ByteReader(UnsafeRawBufferPointer(buffer)))
                parser.skipSP()
                let entries = try parser.parseDictionaryMembers()
                parser.skipSP()
                guard parser.isAtEnd else {
                    throw .trailingCharacters
                }
                return entries
            }
        }
        return try outcome.get()
    }

    /// A bounded forward cursor over a field value's ASCII octets (RFC 8941 §4.2).
    ///
    /// Backed by a borrowed ``ByteReader`` (a `~Escapable` cursor over a `RawSpan`) rather than an owned
    /// `[UInt8]`, so parsing reads the field value's UTF-8 in place — no `Array(source.utf8)` copy. The
    /// three entry points borrow the bytes via `String.withUTF8`.
    struct Parser: ~Escapable {
        private var reader: ByteReader

        @_lifetime(copy reader)
        init(_ reader: consuming ByteReader) {
            self.reader = reader
        }

        var isAtEnd: Bool {
            reader.isAtEnd
        }

        private var current: UInt8? {
            reader.peek()
        }

        private mutating func advance() {
            reader.advance()
        }

        mutating func skipSP() {
            while current == Self.sp {
                advance()
            }
        }

        private mutating func skipOWS() {
            while current == Self.sp || current == Self.htab {
                advance()
            }
        }

        // MARK: Containers

        mutating func parseListMembers() throws(ParseError) -> [Member] {
            var members: [Member] = []
            while !isAtEnd {
                members.append(try parseItemOrInnerList())
                skipOWS()
                if isAtEnd {
                    return members
                }
                guard current == Self.comma else {
                    throw .expectedComma
                }
                advance()
                skipOWS()
                if isAtEnd {
                    throw .trailingComma
                }
            }
            return members
        }

        mutating func parseDictionaryMembers() throws(ParseError) -> [DictionaryEntry] {
            var entries: [DictionaryEntry] = []
            while !isAtEnd {
                let key = try parseKey()
                let value = try parseDictionaryValue()
                if let existing = entries.firstIndex(where: { $0.key == key }) {
                    entries[existing] = DictionaryEntry(key: key, value: value)
                }
                else {
                    entries.append(DictionaryEntry(key: key, value: value))
                }
                skipOWS()
                if isAtEnd {
                    return entries
                }
                guard current == Self.comma else {
                    throw .expectedComma
                }
                advance()
                skipOWS()
                if isAtEnd {
                    throw .trailingComma
                }
            }
            return entries
        }

        private mutating func parseDictionaryValue() throws(ParseError) -> Member {
            if current == Self.equals {
                advance()
                return try parseItemOrInnerList()
            }
            return .item(Item(.boolean(true), parameters: try parseParameters()))
        }

        private mutating func parseItemOrInnerList() throws(ParseError) -> Member {
            if current == Self.openParen {
                return .innerList(try parseInnerList())
            }
            return .item(try parseItem())
        }

        private mutating func parseInnerList() throws(ParseError) -> InnerList {
            advance()  // consume "("
            var items: [Item] = []
            while true {
                skipSP()
                if current == Self.closeParen {
                    advance()
                    return InnerList(items, parameters: try parseParameters())
                }
                items.append(try parseItem())
                guard let next = current, next == Self.sp || next == Self.closeParen else {
                    throw .invalidInnerList
                }
            }
        }

        // MARK: Item + parameters

        mutating func parseItem() throws(ParseError) -> Item {
            let bare = try parseBareItem()
            return Item(bare, parameters: try parseParameters())
        }

        private mutating func parseParameters() throws(ParseError) -> Parameters {
            var parameters = Parameters()
            while current == Self.semicolon {
                advance()
                skipSP()
                let key = try parseKey()
                var value = BareItem.boolean(true)
                if current == Self.equals {
                    advance()
                    value = try parseBareItem()
                }
                parameters.set(key, to: value)
            }
            return parameters
        }

        private mutating func parseKey() throws(ParseError) -> String {
            guard let first = current, Self.isLCAlpha(first) || first == Self.star else {
                throw .invalidKey
            }
            var key: [UInt8] = []
            while let character = current, Self.isKeyByte(character) {
                key.append(character)
                advance()
            }
            return String(decoding: key, as: Unicode.UTF8.self)
        }

        // MARK: Bare items

        private mutating func parseBareItem() throws(ParseError) -> BareItem {
            guard let character = current else {
                throw .unexpectedEndOfInput
            }
            if character == Self.dash || Self.isDigit(character) {
                return try parseNumber()
            }
            if character == Self.dquote {
                return try parseString()
            }
            if character == Self.star || Self.isAlpha(character) {
                return .token(parseToken())
            }
            if character == Self.colon {
                return try parseByteSequence()
            }
            if character == Self.question {
                return try parseBoolean()
            }
            throw .invalidBareItem
        }

        private mutating func parseNumber() throws(ParseError) -> BareItem {
            var sign: Int64 = 1
            if current == Self.dash {
                advance()
                sign = -1
            }
            guard let first = current, Self.isDigit(first) else {
                throw .invalidBareItem
            }
            var digits: [UInt8] = []
            var isDecimal = false
            while let character = current {
                if Self.isDigit(character) {
                    digits.append(character)
                }
                else if !isDecimal, character == Self.dot {
                    guard digits.count <= 12 else {
                        throw .invalidDecimal
                    }
                    isDecimal = true
                    digits.append(character)
                }
                else {
                    break
                }
                advance()
                if !isDecimal, digits.count > 15 {
                    throw .integerOutOfRange
                }
                if isDecimal, digits.count > 16 {
                    throw .invalidDecimal
                }
            }
            return try Self.makeNumber(digits: digits, sign: sign, isDecimal: isDecimal)
        }

        private mutating func parseString() throws(ParseError) -> BareItem {
            advance()  // consume opening DQUOTE
            var value: [UInt8] = []
            while let character = current {
                advance()
                if character == Self.backslash {
                    guard let escaped = current else {
                        throw .unterminatedString
                    }
                    advance()
                    guard escaped == Self.dquote || escaped == Self.backslash else {
                        throw .invalidEscapeSequence
                    }
                    value.append(escaped)
                }
                else if character == Self.dquote {
                    return .string(String(decoding: value, as: Unicode.UTF8.self))
                }
                else if character < 0x20 || character >= 0x7F {
                    throw .invalidStringCharacter
                }
                else {
                    value.append(character)
                }
            }
            throw .unterminatedString
        }

        private mutating func parseToken() -> String {
            var token: [UInt8] = []
            while let character = current, Self.isTokenByte(character) {
                token.append(character)
                advance()
            }
            return String(decoding: token, as: Unicode.UTF8.self)
        }

        private mutating func parseByteSequence() throws(ParseError) -> BareItem {
            advance()  // consume opening ":"
            var encoded: [UInt8] = []
            while let character = current {
                advance()
                if character == Self.colon {
                    guard let bytes = Self.decodeBase64(encoded) else {
                        throw .invalidByteSequence
                    }
                    return .byteSequence(bytes)
                }
                guard Self.isBase64Byte(character) else {
                    throw .invalidByteSequence
                }
                encoded.append(character)
            }
            throw .unterminatedByteSequence
        }

        private mutating func parseBoolean() throws(ParseError) -> BareItem {
            advance()  // consume "?"
            guard let character = current else {
                throw .invalidBoolean
            }
            advance()
            if character == Self.one {
                return .boolean(true)
            }
            if character == Self.zero {
                return .boolean(false)
            }
            throw .invalidBoolean
        }
    }
}
