//
//  HeaderFieldTests.swift
//  HTTPCoreTests
//
//  RED→GREEN driver for the shared ``HeaderField`` (RFC 7541 §1.3 / RFC 9204 §3.1) — the name/value
//  pair hoisted so HPACK and QPACK share one type, including the §4.1 / §3.2.1 dynamic-table sizing.
//

import Testing

@testable import HTTPCore

@Suite("HeaderField — shared header name/value pair")
struct HeaderFieldTests {
    @Test("a value defaults to empty")
    func defaultValueIsEmpty() {
        let field = HeaderField(name: ":authority")
        #expect(field.name == ":authority")
        #expect(field.value.isEmpty)
    }

    @Test(
        "table size is name + value + 32 octets (RFC 7541 §4.1 / RFC 9204 §3.2.1)",
        arguments: [
            (name: "", value: "", size: 32),
            (name: ":method", value: "GET", size: 7 + 3 + 32),
            (name: "content-type", value: "text/plain", size: 12 + 10 + 32)
        ] as [(name: String, value: String, size: Int)])
    func tableSize(_ testCase: (name: String, value: String, size: Int)) {
        #expect(HeaderField(name: testCase.name, value: testCase.value).tableSize == testCase.size)
    }

    @Test("equality and hashing fold name and value together")
    func equatableHashable() {
        let a = HeaderField(name: ":status", value: "200")
        let b = HeaderField(name: ":status", value: "200")
        let c = HeaderField(name: ":status", value: "404")
        #expect(a == b)
        #expect(a != c)
        #expect(Set([a, b, c]).count == 2)
    }
}
