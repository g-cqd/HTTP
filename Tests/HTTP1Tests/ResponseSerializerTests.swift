//
//  ResponseSerializerTests.swift
//  HTTP1Tests
//
//  RED→GREEN driver for RFC 9112 §3.1/§5 response serialization.
//

import HTTPCore
import Testing

@testable import HTTP1

@Suite("RFC 9112 §3.1/§5 — response serialization")
struct ResponseSerializerTests {
    private func serialize(_ response: HTTPResponse, body: String = "") -> String {
        let bytes = ResponseSerializer.serialize(response, body: Array(body.utf8))
        return String(decoding: bytes, as: Unicode.UTF8.self)
    }

    @Test("serializes status-line, headers, and body with auto Content-Length")
    func serializesResponse() {
        var fields = HTTPFields()
        fields.append("text/plain", for: .contentType)
        let wire = serialize(HTTPResponse(status: .ok, headerFields: fields), body: "hello")
        #expect(
            wire == "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 5\r\n\r\nhello")
    }

    @Test("auto-frames an empty body as Content-Length: 0")
    func emptyBody() {
        let wire = serialize(HTTPResponse(status: .notFound))
        #expect(wire == "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n")
    }

    @Test("omits the body but keeps the equivalent Content-Length (HEAD, RFC 9112 §6.3)")
    func omitsBodyForHead() {
        let bytes = ResponseSerializer.serialize(
            HTTPResponse(status: .ok),
            body: Array("0123456789".utf8),
            omitBody: true
        )
        let wire = String(decoding: bytes, as: Unicode.UTF8.self)
        #expect(wire == "HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\n")
    }

    @Test("does not override an explicit Content-Length")
    func explicitContentLength() {
        var fields = HTTPFields()
        fields.append("10", for: .contentLength)
        let wire = serialize(HTTPResponse(status: .ok, headerFields: fields), body: "hi")
        #expect(wire == "HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\nhi")
    }

    @Test("omits the reason-phrase for unregistered codes (RFC 9112 §4)")
    func unregisteredStatusCode() throws {
        let status = try #require(HTTPStatus(code: 299))
        let wire = serialize(HTTPResponse(status: status))
        #expect(wire == "HTTP/1.1 299 \r\ncontent-length: 0\r\n\r\n")
    }
}
