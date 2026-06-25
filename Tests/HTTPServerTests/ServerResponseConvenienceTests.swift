//
//  ServerResponseConvenienceTests.swift
//  HTTPServerTests
//
//  The ergonomic ``ServerResponse`` constructors: text / JSON content types and a bodiless status.
//

import HTTPCore
import Testing

@testable import HTTPServer

@Suite("ServerResponse conveniences")
struct ServerResponseConvenienceTests {
    @Test("text sets text/plain; charset=utf-8 with the body")
    func text() {
        let response = ServerResponse.text("hi")
        #expect(response.head.status == .ok)
        #expect(response.head.headerFields[.contentType] == "text/plain; charset=utf-8")
        #expect(response.body == Array("hi".utf8))
    }

    @Test("json sets application/json and carries the status + body")
    func json() {
        let response = ServerResponse.json(Array("{}".utf8), status: .created)
        #expect(response.head.status == .created)
        #expect(response.head.headerFields[.contentType] == "application/json")
        #expect(response.body == Array("{}".utf8))
    }

    @Test("status makes a bodiless response")
    func bodilessStatus() {
        let response = ServerResponse.status(.noContent)
        #expect(response.head.status == .noContent)
        #expect(response.body.isEmpty)
    }
}
