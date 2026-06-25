//
//  StructuredFieldsSerializationTests.swift
//  HTTPCoreTests
//
//  RFC 8941 §4.1 serializer: canonical output for every bare type and container, decimal rounding,
//  parse↔serialize round-trips, and the typed failure for each value the wire grammar cannot carry
//  (out-of-range integer, bad token / key / string octet).
//

import HTTPCore
import Testing

@Suite("RFC 8941 Structured Fields — serializer")
struct StructuredFieldsSerializationTests {
    typealias SF = StructuredFields

    @Test("bare items serialize to their canonical form")
    func bareItems() throws {
        #expect(try SF.serialize(SF.Item(.integer(42))) == "42")
        #expect(try SF.serialize(SF.Item(.integer(-42))) == "-42")
        #expect(try SF.serialize(SF.Item(.string("a\"b"))) == "\"a\\\"b\"")
        #expect(try SF.serialize(SF.Item(.token("text/html"))) == "text/html")
        #expect(try SF.serialize(SF.Item(.byteSequence(Array("hello".utf8)))) == ":aGVsbG8=:")
        #expect(try SF.serialize(SF.Item(.boolean(true))) == "?1")
        #expect(try SF.serialize(SF.Item(.boolean(false))) == "?0")
    }

    @Test("decimals round to three fractional digits with at least one")
    func decimals() throws {
        #expect(try SF.serialize(SF.Item(.decimal(4.5))) == "4.5")
        #expect(try SF.serialize(SF.Item(.decimal(1.0))) == "1.0")
        #expect(try SF.serialize(SF.Item(.decimal(1.25))) == "1.25")
        #expect(try SF.serialize(SF.Item(.decimal(0.001))) == "0.001")
        #expect(try SF.serialize(SF.Item(.decimal(-2.5))) == "-2.5")
    }

    @Test("containers and parameters serialize canonically")
    func containers() throws {
        let params = SF.Parameters([SF.Parameter(key: "q", value: .decimal(0.5))])
        let item = SF.Item(.token("text/html"), parameters: params)
        #expect(try SF.serialize(item) == "text/html;q=0.5")

        let list: [SF.Member] = [.item(SF.Item(.integer(1))), .item(SF.Item(.integer(2)))]
        #expect(try SF.serialize(list: list) == "1, 2")

        let inner = SF.InnerList([SF.Item(.token("a")), SF.Item(.token("b"))])
        #expect(try SF.serialize(list: [.innerList(inner)]) == "(a b)")

        let dict = [
            SF.DictionaryEntry(key: "a", value: .item(SF.Item(.integer(1)))),
            SF.DictionaryEntry(key: "b", value: .item(SF.Item(.boolean(true))))
        ]
        #expect(try SF.serialize(dictionary: dict) == "a=1, b")
    }

    @Test("round-trip lists: parse then serialize yields the canonical input")
    func roundTripLists() throws {
        for input in ["1, 2, 3", "(a b);n=1, c"] {
            #expect(try SF.serialize(list: SF.parseList(input)) == input)
        }
    }

    @Test("round-trip dictionaries: parse then serialize yields the canonical input")
    func roundTripDictionaries() throws {
        for input in ["a=1, b, c=?0", "u=1, i"] {
            #expect(try SF.serialize(dictionary: SF.parseDictionary(input)) == input)
        }
    }

    @Test("an unrepresentable value fails with its specific error")
    func validationFailures() {
        #expect(throws: SF.SerializeError.integerOutOfRange) {
            try SF.serialize(SF.Item(.integer(1_000_000_000_000_000)))
        }
        #expect(throws: SF.SerializeError.invalidToken) {
            try SF.serialize(SF.Item(.token("bad token")))
        }
        #expect(throws: SF.SerializeError.invalidToken) {
            try SF.serialize(SF.Item(.token("")))
        }
        #expect(throws: SF.SerializeError.invalidStringCharacter) {
            try SF.serialize(SF.Item(.string("a\u{7F}")))
        }
        #expect(throws: SF.SerializeError.invalidKey) {
            let entry = SF.DictionaryEntry(key: "Bad", value: .item(SF.Item(.boolean(true))))
            try SF.serialize(dictionary: [entry])
        }
    }
}
