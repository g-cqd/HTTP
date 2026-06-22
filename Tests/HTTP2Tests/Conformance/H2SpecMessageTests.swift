//
//  H2SpecMessageTests.swift
//  HTTP2Tests
//
//  h2spec conformance — the `http2` group, RFC 7540/9113 §8 HTTP Message Exchanges: §8.1 request/
//  response, §8.1.2 header fields, §8.1.2.1 pseudo-headers, §8.1.2.2 connection-specific fields,
//  §8.1.2.3 request pseudo-headers, §8.1.2.6 malformed requests, and §8.2 server push. Malformed
//  requests are stream errors (RST_STREAM PROTOCOL_ERROR, §8.1.1); a client PUSH_PROMISE is fatal.
//
//  Two findings are pre-staged with `withKnownIssue` (engine fix to follow, per the approved plan):
//   • F2 — a second HEADERS without END_STREAM is escalated to a *connection* error; §8.1 wants a
//     *stream* error PROTOCOL_ERROR.
//   • F3 — a pseudo-header carried in trailers is not rejected: the trailers path advances the stream
//     state without re-validating fields, so §8.1.2.1's "pseudo-header in trailers" passes silently.
//

import HPACK
import HTTPCore
import Testing

@testable import HTTP2

/// A field name/value pair as an `HPACKField` (file-scope so it is usable in `@Test(arguments:)`).
private func hf(_ name: String, _ value: String) -> HPACKField {
    HPACKField(name: name, value: value)
}

@Suite("h2spec http2 §8 — HTTP Message Exchanges")
struct H2SpecMessageTests {

    // MARK: §8.1 HTTP Request/Response Exchange

    @Test("8.1/1 — a second HEADERS frame without END_STREAM is a stream PROTOCOL_ERROR (§8.1)")
    func secondHeadersWithoutEndStreamIsStreamError() throws {
        var connection = try H2Wire.handshaked()
        var wire = H2Wire.openStream(streamID: 1)  // first HEADERS, stream open
        wire += H2Wire.headers(
            streamID: 1, fields: H2Wire.requestFields(method: "POST"), endStream: false)
        withKnownIssue(
            "F2 — RFC 9113 §8.1: trailers without END_STREAM escalated to a connection error"
        ) {
            H2Wire.expectStreamError(.protocolError, on: 1, feeding: wire, connection: &connection)
        }
    }

    // MARK: §8.1.2 HTTP Header Fields

    @Test("8.1.2/1 — a header field name in uppercase is a stream PROTOCOL_ERROR (§8.1.2)")
    func uppercaseFieldNameIsStreamError() throws {
        var connection = try H2Wire.handshaked()
        let fields = H2Wire.requestFields(extra: [hf("X-Test", "1")])
        H2Wire.expectStreamError(
            .protocolError, on: 1, feeding: H2Wire.headers(streamID: 1, fields: fields),
            connection: &connection)
    }

    // MARK: §8.1.2.1 Pseudo-Header Fields

    @Test(
        "8.1.2.1 — a malformed pseudo-header is a stream PROTOCOL_ERROR (§8.1.2.1)",
        arguments: [
            (
                label: "unknown pseudo-header",
                fields: [
                    hf(":method", "GET"), hf(":scheme", "https"), hf(":path", "/"),
                    hf(":authority", "example.com"), hf(":unknown", "x"),
                ]
            ),
            (
                label: "response pseudo-header in a request",
                fields: [
                    hf(":method", "GET"), hf(":scheme", "https"), hf(":path", "/"),
                    hf(":status", "200"),
                ]
            ),
            (
                label: "pseudo-header after a regular field",
                fields: [
                    hf(":method", "GET"), hf(":scheme", "https"), hf(":path", "/"),
                    hf("x", "1"), hf(":authority", "example.com"),
                ]
            ),
        ])
    func malformedPseudoHeaderIsStreamError(
        _ testCase: (label: String, fields: [HPACKField])
    ) throws {
        var connection = try H2Wire.handshaked()
        H2Wire.expectStreamError(
            .protocolError, on: 1, feeding: H2Wire.headers(streamID: 1, fields: testCase.fields),
            connection: &connection)
    }

    @Test(
        "8.1.2.1/3 — a pseudo-header field carried as a trailer is a stream PROTOCOL_ERROR (§8.1.2.1)"
    )
    func pseudoHeaderInTrailersIsStreamError() throws {
        var connection = try H2Wire.handshaked()
        var wire = H2Wire.openStream(streamID: 1)  // request open, awaiting trailers
        wire += H2Wire.headers(streamID: 1, fields: [hf(":status", "200")], endStream: true)
        withKnownIssue("F3 — RFC 9113 §8.1.2.1: trailers bypass pseudo-header validation") {
            H2Wire.expectStreamError(.protocolError, on: 1, feeding: wire, connection: &connection)
        }
    }

    // MARK: §8.1.2.2 Connection-Specific Header Fields

    @Test(
        "8.1.2.2 — a connection-specific header field is a stream PROTOCOL_ERROR (§8.1.2.2)",
        arguments: [
            (
                label: "connection-specific field",
                fields: H2Wire.requestFields(
                    extra: [hf("connection", "keep-alive")])
            ),
            (
                label: "TE with a value other than trailers",
                fields: H2Wire.requestFields(
                    extra: [hf("te", "gzip")])
            ),
        ])
    func connectionSpecificFieldIsStreamError(
        _ testCase: (label: String, fields: [HPACKField])
    )
        throws
    {
        var connection = try H2Wire.handshaked()
        H2Wire.expectStreamError(
            .protocolError, on: 1, feeding: H2Wire.headers(streamID: 1, fields: testCase.fields),
            connection: &connection)
    }

    // MARK: §8.1.2.3 Request Pseudo-Header Fields

    @Test(
        "8.1.2.3 — a missing or duplicated request pseudo-header is a stream PROTOCOL_ERROR (§8.1.2.3)",
        arguments: [
            (label: "empty :path", fields: H2Wire.requestFields(path: "")),
            (
                label: "omit :method",
                fields: [hf(":scheme", "https"), hf(":path", "/"), hf(":authority", "example.com")]
            ),
            (
                label: "omit :scheme",
                fields: [hf(":method", "GET"), hf(":path", "/"), hf(":authority", "example.com")]
            ),
            (
                label: "omit :path",
                fields: [
                    hf(":method", "GET"), hf(":scheme", "https"),
                    hf(":authority", "example.com"),
                ]
            ),
            (
                label: "duplicate :method",
                fields: [
                    hf(":method", "GET"), hf(":method", "POST"), hf(":scheme", "https"),
                    hf(":path", "/"), hf(":authority", "example.com"),
                ]
            ),
            (
                label: "duplicate :scheme",
                fields: [
                    hf(":method", "GET"), hf(":scheme", "https"), hf(":scheme", "http"),
                    hf(":path", "/"), hf(":authority", "example.com"),
                ]
            ),
            (
                label: "duplicate :path",
                fields: [
                    hf(":method", "GET"), hf(":scheme", "https"), hf(":path", "/"),
                    hf(":path", "/x"), hf(":authority", "example.com"),
                ]
            ),
        ])
    func malformedRequestPseudoHeaderIsStreamError(
        _ testCase: (label: String, fields: [HPACKField])
    ) throws {
        var connection = try H2Wire.handshaked()
        H2Wire.expectStreamError(
            .protocolError, on: 1, feeding: H2Wire.headers(streamID: 1, fields: testCase.fields),
            connection: &connection)
    }

    // MARK: §8.1.2.6 Malformed Requests and Responses

    @Test(
        "8.1.2.6/1 — content-length not matching the DATA length is a stream PROTOCOL_ERROR (§8.1.2.6)"
    )
    func contentLengthMismatchSingleDataIsStreamError() throws {
        var connection = try H2Wire.handshaked()
        var wire = H2Wire.headers(
            streamID: 1,
            fields: H2Wire.requestFields(method: "POST", extra: [hf("content-length", "5")]),
            endStream: false)
        wire += H2Wire.data(streamID: 1, payload: Array("ab".utf8), endStream: true)  // 2 ≠ 5
        H2Wire.expectStreamError(.protocolError, on: 1, feeding: wire, connection: &connection)
    }

    @Test(
        "8.1.2.6/2 — content-length not matching the summed DATA length is a stream PROTOCOL_ERROR (§8.1.2.6)"
    )
    func contentLengthMismatchMultipleDataIsStreamError() throws {
        var connection = try H2Wire.handshaked()
        var wire = H2Wire.headers(
            streamID: 1,
            fields: H2Wire.requestFields(method: "POST", extra: [hf("content-length", "10")]),
            endStream: false)
        wire += H2Wire.data(streamID: 1, payload: Array("abc".utf8), endStream: false)
        wire += H2Wire.data(streamID: 1, payload: Array("de".utf8), endStream: true)  // 5 ≠ 10
        H2Wire.expectStreamError(.protocolError, on: 1, feeding: wire, connection: &connection)
    }

    // MARK: §8.2 Server Push

    @Test("8.2/1 — a client-sent PUSH_PROMISE frame is a connection PROTOCOL_ERROR (§8.2)")
    func clientPushPromiseIsConnectionError() throws {
        var connection = try H2Wire.handshaked()
        H2Wire.expectConnectionError(
            .protocolError, feeding: H2Wire.pushPromise(onStream: 1), on: &connection)
    }

    // h2spec coverage: §8.1 (1) + §8.1.2 (1) + §8.1.2.1 (4) + §8.1.2.2 (2) + §8.1.2.3 (7)
    //                  + §8.1.2.6 (2) + §8.2 (1) = 18 cases.
}
