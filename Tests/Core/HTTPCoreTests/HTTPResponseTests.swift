//
//  HTTPResponseTests.swift
//  HTTPCoreTests
//
//  RED→GREEN driver for the HTTPResponse message value type.
//

import Testing

@testable import HTTPCore

@Suite("RFC 9110 §3/§15 — HTTPResponse")
struct HTTPResponseTests {
    @Test("stores its status and fields")
    func storesStatusAndFields() {
        var fields = HTTPFields()
        fields.append("text/plain", for: .contentType)
        let response = HTTPResponse(status: .ok, headerFields: fields)
        #expect(response.status == .ok)
        #expect(response.status.kind == .successful)
        #expect(response.headerFields[.contentType] == "text/plain")
    }

    @Test("defaults to empty header fields")
    func defaultsToEmptyFields() {
        let response = HTTPResponse(status: .notFound)
        #expect(response.status.code == 404)
        #expect(response.headerFields.isEmpty)
    }
}
