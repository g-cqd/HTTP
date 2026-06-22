//
//  HTTP2RequestMapperTests.swift
//  HTTP2Tests
//
//  RED→GREEN driver for RFC 9113 §8.3 request mapping: the four pseudo-headers and regular fields, the
//  ordering / duplicate / unknown / missing pseudo-header rules, and the §8.2 lowercase and
//  connection-specific / TE restrictions.
//

import HPACK
import HTTPCore
import Testing

@testable import HTTP2

@Suite("RFC 9113 §8.3 — request mapping")
struct HTTP2RequestMapperTests {

    private let stream = HTTP2StreamID(1)

    private func make(_ fields: [HPACKField]) throws -> HTTPRequest {
        try HTTP2RequestMapper.makeRequest(from: fields, streamID: stream).request
    }

    private func errorCode(_ fields: [HPACKField]) -> HTTP2ErrorCode? {
        do {
            _ = try make(fields)
            return nil
        } catch let error as HTTP2Error {
            return error.code
        } catch {
            return nil
        }
    }

    /// A minimal valid pseudo-header set, plus any extra fields.
    private func request(adding extras: [HPACKField]) -> [HPACKField] {
        [
            HPACKField(name: ":method", value: "GET"),
            HPACKField(name: ":scheme", value: "https"),
            HPACKField(name: ":path", value: "/"),
        ] + extras
    }

    @Test("maps the four request pseudo-headers and regular fields")
    func mapsRequest() throws {
        let mapped = try make([
            HPACKField(name: ":method", value: "GET"),
            HPACKField(name: ":scheme", value: "https"),
            HPACKField(name: ":authority", value: "example.com"),
            HPACKField(name: ":path", value: "/index.html"),
            HPACKField(name: "accept", value: "text/html"),
        ])
        #expect(mapped.method == .get)
        #expect(mapped.scheme == "https")
        #expect(mapped.authority == "example.com")
        #expect(mapped.path == "/index.html")
        #expect(mapped.headerFields[.accept] == "text/html")
    }

    @Test("a pseudo-header after a regular field is malformed (§8.3)")
    func pseudoAfterRegular() {
        #expect(
            errorCode([
                HPACKField(name: "accept", value: "text/html"),
                HPACKField(name: ":method", value: "GET"),
            ]) == .protocolError)
    }

    @Test("a duplicate pseudo-header is malformed")
    func duplicatePseudo() {
        #expect(
            errorCode([
                HPACKField(name: ":method", value: "GET"),
                HPACKField(name: ":method", value: "POST"),
            ]) == .protocolError)
    }

    @Test("an unknown / response pseudo-header in a request is malformed (§8.3)")
    func unknownPseudo() {
        #expect(errorCode([HPACKField(name: ":status", value: "200")]) == .protocolError)
    }

    @Test("a missing required pseudo-header is malformed (§8.3.1)")
    func missingRequired() {
        #expect(errorCode([HPACKField(name: ":method", value: "GET")]) == .protocolError)
    }

    @Test("an empty :path is malformed (§8.3.1)")
    func emptyPath() {
        #expect(
            errorCode([
                HPACKField(name: ":method", value: "GET"),
                HPACKField(name: ":scheme", value: "https"),
                HPACKField(name: ":path", value: ""),
            ]) == .protocolError)
    }

    @Test("an uppercase field name is malformed (§8.2.1)")
    func uppercaseFieldName() {
        #expect(
            errorCode(request(adding: [HPACKField(name: "Accept", value: "x")])) == .protocolError)
    }

    @Test("a connection-specific field is forbidden (§8.2.2)")
    func forbiddenConnectionField() {
        #expect(
            errorCode(request(adding: [HPACKField(name: "connection", value: "keep-alive")]))
                == .protocolError)
    }

    @Test("TE other than 'trailers' is forbidden, but 'trailers' is allowed (§8.2.2)")
    func teRestriction() throws {
        #expect(
            errorCode(request(adding: [HPACKField(name: "te", value: "gzip")])) == .protocolError)
        let ok = try make(request(adding: [HPACKField(name: "te", value: "trailers")]))
        #expect(ok.method == .get)
    }
}
