//
//  StructuredFieldsTests.swift
//  HTTPCoreTests
//
//  RFC 8941 parser: every bare-item type, parameters, lists / inner lists, dictionaries, the §3.3.1/
//  §3.3.2 numeric caps, and the fail-closed error for each malformed shape (mutation-resistant — each
//  rejection asserts its specific ParseError, not merely "throws"). Closes with the RFC 9218 `Priority`
//  header, the motivating real-world consumer.
//

import HTTPCore
import Testing

@Suite("RFC 8941 Structured Fields — parser")
struct StructuredFieldsTests {
    typealias SF = StructuredFields

    // MARK: Bare items

    @Test("integers: sign, zero, and the 15-digit magnitude ceiling")
    func integers() throws {
        #expect(try SF.parseItem("42").bareItem == .integer(42))
        #expect(try SF.parseItem("-42").bareItem == .integer(-42))
        #expect(try SF.parseItem("0").bareItem == .integer(0))
        #expect(try SF.parseItem("999999999999999").bareItem == .integer(999_999_999_999_999))
        #expect(throws: SF.ParseError.integerOutOfRange) { try SF.parseItem("1000000000000000") }
    }

    @Test("decimals: fractional digits, sign, the 3-fraction- and 12-integer-digit caps (§4.2.4)")
    func decimals() throws {
        #expect(try SF.parseItem("4.5").bareItem == .decimal(4.5))
        #expect(try SF.parseItem("-1.25").bareItem == .decimal(-1.25))
        #expect(try SF.parseItem("1.000").bareItem == .decimal(1.0))
        #expect(try SF.parseItem("123456789012.5").bareItem == .decimal(123_456_789_012.5))
        #expect(throws: SF.ParseError.invalidDecimal) { try SF.parseItem("1.2345") }
        #expect(throws: SF.ParseError.invalidDecimal) { try SF.parseItem("1.") }
        // >12 digits before the decimal point is rejected (matches the serializer — symmetric codec).
        #expect(throws: SF.ParseError.invalidDecimal) { try SF.parseItem("1234567890123.5") }
    }

    @Test("strings: plain, and the two legal escapes")
    func strings() throws {
        #expect(try SF.parseItem("\"hello\"").bareItem == .string("hello"))
        #expect(try SF.parseItem("\"a\\\"b\"").bareItem == .string("a\"b"))
        #expect(try SF.parseItem("\"a\\\\b\"").bareItem == .string("a\\b"))
    }

    @Test("tokens: leading star and the extra ':' and '/' octets")
    func tokens() throws {
        #expect(try SF.parseItem("foo123").bareItem == .token("foo123"))
        #expect(try SF.parseItem("*").bareItem == .token("*"))
        #expect(try SF.parseItem("text/html").bareItem == .token("text/html"))
    }

    @Test("byte sequences: padded base64 round-trips to the original octets")
    func byteSequences() throws {
        #expect(try SF.parseItem(":aGVsbG8=:").bareItem == .byteSequence(Array("hello".utf8)))
        #expect(try SF.parseItem("::").bareItem == .byteSequence([]))
    }

    @Test("booleans: ?1 and ?0")
    func booleans() throws {
        #expect(try SF.parseItem("?1").bareItem == .boolean(true))
        #expect(try SF.parseItem("?0").bareItem == .boolean(false))
    }

    // MARK: Parameters + containers

    @Test("parameters: a valued parameter and a bare (boolean-true) parameter")
    func parameters() throws {
        let item = try SF.parseItem("text/html;q=0.5;flag")
        #expect(item.bareItem == .token("text/html"))
        #expect(item.parameters["q"] == .decimal(0.5))
        #expect(item.parameters["flag"] == .boolean(true))
    }

    @Test("list: items and an inner list with its own parameters")
    func lists() throws {
        #expect(try SF.parseList("1, 2, 3").count == 3)
        let mixed = try SF.parseList("(a b);n=1, c")
        #expect(mixed.count == 2)
        #expect(
            mixed[0]
                == .innerList(
                    SF.InnerList(
                        [SF.Item(.token("a")), SF.Item(.token("b"))],
                        parameters: SF.Parameters([SF.Parameter(key: "n", value: .integer(1))])
                    )
                )
        )
        #expect(mixed[1] == .item(SF.Item(.token("c"))))
    }

    @Test("dictionary: valued key, bare (true) key, and last-wins on a duplicate key")
    func dictionaries() throws {
        let entries = try SF.parseDictionary("a=1, b, a=2")
        #expect(entries.count == 2)  // duplicate "a" collapses, keeping position
        #expect(entries[0] == SF.DictionaryEntry(key: "a", value: .item(SF.Item(.integer(2)))))
        #expect(entries[1] == SF.DictionaryEntry(key: "b", value: .item(SF.Item(.boolean(true)))))
    }

    @Test("empty input: an empty list/dictionary, but an empty item is rejected")
    func emptyInputs() throws {
        #expect(try SF.parseList("").isEmpty)
        #expect(try SF.parseList("   ").isEmpty)
        #expect(try SF.parseDictionary("").isEmpty)
        #expect(throws: SF.ParseError.empty) { try SF.parseItem("") }
    }

    @Test("RFC 9218 Priority: u (urgency) integer + i (incremental) boolean")
    func priorityHeader() throws {
        let entries = try SF.parseDictionary("u=1, i")
        #expect(entries[0] == SF.DictionaryEntry(key: "u", value: .item(SF.Item(.integer(1)))))
        #expect(entries[1] == SF.DictionaryEntry(key: "i", value: .item(SF.Item(.boolean(true)))))
    }

    // MARK: Malformed → specific fail-closed error

    @Test(
        "a malformed item is rejected with its specific error",
        arguments: [
            (input: "1 2", error: SF.ParseError.trailingCharacters),
            (input: "%", error: .invalidBareItem),
            (input: "\"oops", error: .unterminatedString),
            (input: "\"\\x\"", error: .invalidEscapeSequence),
            (input: ":!:", error: .invalidByteSequence),
            (input: ":aGVsbG8=", error: .unterminatedByteSequence),
            (input: "?2", error: .invalidBoolean)
        ]
    )
    func malformedItem(_ testCase: (input: String, error: SF.ParseError)) {
        #expect(throws: testCase.error) { try SF.parseItem(testCase.input) }
    }

    @Test(
        "a malformed list is rejected with its specific error",
        arguments: [
            (input: "a b", error: SF.ParseError.expectedComma),
            (input: "1, 2,", error: .trailingComma),
            (input: "(1,2)", error: .invalidInnerList)
        ]
    )
    func malformedList(_ testCase: (input: String, error: SF.ParseError)) {
        #expect(throws: testCase.error) { try SF.parseList(testCase.input) }
    }

    @Test("a malformed dictionary key is rejected")
    func malformedDictionaryKey() {
        #expect(throws: SF.ParseError.invalidKey) { try SF.parseDictionary("1=2") }
    }
}
