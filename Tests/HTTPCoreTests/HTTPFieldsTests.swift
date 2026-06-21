//
//  HTTPFieldsTests.swift
//  HTTPCoreTests
//
//  RED→GREEN driver for RFC 9110 §5.3 field-collection semantics (lookup, combining, order).
//

import Testing

@testable import HTTPCore

@Suite("RFC 9110 §5.3 — HTTPFields")
struct HTTPFieldsTests {

    private func field(_ name: HTTPFieldName, _ value: String) -> HTTPField {
        guard let field = HTTPField(name: name, value: value) else {
            Issue.record("test fixture produced an invalid field")
            return HTTPField(uncheckedName: name, value: "")
        }
        return field
    }

    @Test("an empty collection has no fields")
    func emptyCollection() {
        let fields = HTTPFields()
        #expect(fields.isEmpty)
        #expect(fields.count == 0)
        #expect(fields[.contentType] == nil)
        #expect(!fields.contains(.contentType))
    }

    @Test("append then look up by (case-insensitive) name")
    func appendAndLookup() {
        var fields = HTTPFields()
        fields.append(field(HTTPFieldName("Content-Type") ?? .contentType, "text/html"))
        #expect(fields[.contentType] == "text/html")
        #expect(fields.contains(.contentType))
        #expect(fields.count == 1)
    }

    @Test("repeated field lines combine in order with \", \" (RFC 9110 §5.3)")
    func combinesRepeatedValues() {
        var fields = HTTPFields()
        fields.append(field(.accept, "text/html"))
        fields.append(field(.accept, "application/json"))
        #expect(fields[.accept] == "text/html, application/json")
    }

    @Test("values(for:) returns each line separately (e.g. for Set-Cookie)")
    func individualValues() {
        var fields = HTTPFields()
        fields.append(field(.setCookie, "a=1"))
        fields.append(field(.setCookie, "b=2"))
        #expect(fields.values(for: .setCookie) == ["a=1", "b=2"])
    }

    @Test("setValue replaces all existing lines of a name")
    func setValueReplaces() {
        var fields = HTTPFields()
        fields.append(field(.accept, "text/html"))
        fields.append(field(.accept, "application/json"))
        let replaced = fields.setValue("*/*", for: .accept)
        #expect(replaced)
        #expect(fields.values(for: .accept) == ["*/*"])
    }

    @Test("removeAll(named:) drops every line of a name")
    func removeAllNamed() {
        var fields = HTTPFields()
        fields.append(field(.accept, "text/html"))
        fields.append(field(.contentType, "text/plain"))
        fields.removeAll(named: .accept)
        #expect(!fields.contains(.accept))
        #expect(fields[.contentType] == "text/plain")
    }

    @Test("wire order is preserved and the collection is iterable")
    func orderPreservedAndIterable() {
        var fields = HTTPFields()
        fields.append(field(.host, "example.com"))
        fields.append(field(.accept, "text/html"))
        fields.append(field(.contentType, "text/plain"))
        #expect(fields.map(\.name) == [.host, .accept, .contentType])
    }

    @Test("rejects an illegal value via the append(_:for:) convenience")
    func appendRejectsIllegalValue() {
        var fields = HTTPFields()
        let appended = fields.append("bad\r\nvalue", for: .contentType)
        #expect(!appended)
        #expect(fields.isEmpty)
    }

    @Test("count(for:) returns the number of matching field lines")
    func countForName() {
        var fields = HTTPFields()
        fields.append(field(.accept, "text/html"))
        fields.append(field(.accept, "application/json"))
        fields.append(field(.host, "example.com"))
        #expect(fields.count(for: .accept) == 2)
        #expect(fields.count(for: .host) == 1)
        #expect(fields.count(for: .contentType) == 0)
    }
}
