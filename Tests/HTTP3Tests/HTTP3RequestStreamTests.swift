//
//  HTTP3RequestStreamTests.swift
//  HTTP3Tests
//
//  RED→GREEN driver for the RFC 9114 §4 request path: a request maps from its QPACK HEADERS (and DATA)
//  to an HTTPRequest event, a response encodes back onto the stream, and the §4.1/§4.2/§4.1.2 message
//  malformations resolve to H3_MESSAGE_ERROR (stream) or the §4.1/§7.1 framing faults to
//  H3_FRAME_UNEXPECTED / H3_FRAME_ERROR (connection), with a QPACK fault to QPACK_DECOMPRESSION_FAILED.
//

import HTTPCore
import QPACK
import Testing

@testable import HTTP3

@Suite("RFC 9114 §4 — HTTP/3 request streams")
struct HTTP3RequestStreamTests: HTTP3WireFixtures {
    private static let stream = QUICStreamID(0)  // client-initiated bidirectional request stream

    @Test("a GET maps to a request event (RFC 9114 §4.3)")
    func getRequest() throws {
        var connection = HTTP3Connection()
        let events = try connection.receive(
            Self.stream, requestStream(requestFieldSection()), fin: true
        )
        guard case .request(let id, let request, let body) = events.first else {
            Issue.record("expected a request event")
            return
        }
        #expect(id == Self.stream)
        #expect(request.method == .get)
        #expect(request.scheme == "https")
        #expect(request.authority == "example.com")
        #expect(request.path == "/")
        #expect(body.isEmpty)
    }

    @Test("a POST body is delivered when content-length matches (§4.1.2)")
    func postBody() throws {
        var connection = HTTP3Connection()
        let section = requestFieldSection(
            method: "POST", extra: [HeaderField(name: "content-length", value: "5")]
        )
        let events = try connection.receive(
            Self.stream, requestStream(section, body: Array("hello".utf8)), fin: true
        )
        guard case .request(_, let request, let body) = events.first else {
            Issue.record("expected a request event")
            return
        }
        #expect(request.method == .post)
        #expect(body == Array("hello".utf8))
    }

    @Test("a response encodes a QPACK HEADERS + DATA frame and FINs the stream (§4.1)")
    func respondEncodes() throws {
        var connection = HTTP3Connection()
        _ = try connection.receive(Self.stream, requestStream(requestFieldSection()), fin: true)
        try connection.respond(to: Self.stream, HTTPResponse(status: .ok), body: Array("ok".utf8))
        guard let sent = sentBytes(&connection, on: Self.stream) else {
            Issue.record("expected a send action")
            return
        }
        #expect(sent.fin)
        let response = try decodeResponse(sent.bytes)
        #expect(response.status == "200")
        #expect(response.body == Array("ok".utf8))
    }

    @Test(
        "a malformed message is a stream error H3_MESSAGE_ERROR (RFC 9114 §4.1.2)",
        arguments: [
            (
                label: "duplicated :method (§4.1.1)",
                fields: [
                    HeaderField(name: ":method", value: "GET"),
                    HeaderField(name: ":method", value: "GET"),
                    HeaderField(name: ":scheme", value: "https"),
                    HeaderField(name: ":path", value: "/")
                ]
            ),
            (
                label: "a mandatory pseudo-header absent (§4.3.1)",
                fields: [
                    HeaderField(name: ":method", value: "GET"),
                    HeaderField(name: ":scheme", value: "https")
                ]
            ),
            (
                label: "a prohibited pseudo-header (§4.3.1)",
                fields: [
                    HeaderField(name: ":method", value: "GET"),
                    HeaderField(name: ":scheme", value: "https"),
                    HeaderField(name: ":path", value: "/"),
                    HeaderField(name: ":unknown", value: "x")
                ]
            ),
            (
                label: "a pseudo-header after a regular field (§4.3.1)",
                fields: [
                    HeaderField(name: ":method", value: "GET"),
                    HeaderField(name: ":scheme", value: "https"),
                    HeaderField(name: ":path", value: "/"),
                    HeaderField(name: "x-test", value: "1"),
                    HeaderField(name: ":authority", value: "example.com")
                ]
            ),
            (
                label: "a connection-specific field (§4.2)",
                fields: [
                    HeaderField(name: ":method", value: "GET"),
                    HeaderField(name: ":scheme", value: "https"),
                    HeaderField(name: ":path", value: "/"),
                    HeaderField(name: "connection", value: "keep-alive")
                ]
            ),
            (
                label: "a TE other than trailers (§4.2)",
                fields: [
                    HeaderField(name: ":method", value: "GET"),
                    HeaderField(name: ":scheme", value: "https"),
                    HeaderField(name: ":path", value: "/"),
                    HeaderField(name: "te", value: "gzip")
                ]
            )
        ] as [(label: String, fields: [HeaderField])])
    func malformedMessage(_ testCase: (label: String, fields: [HeaderField])) throws {
        var connection = HTTP3Connection()
        _ = try connection.receive(
            Self.stream, requestStream(fieldSection(testCase.fields)), fin: true
        )
        #expect(resetStreamCode(&connection) == HTTP3ErrorCode.h3MessageError.rawValue)
    }

    @Test("a content-length that disagrees with the body is H3_MESSAGE_ERROR (§4.1.2)")
    func contentLengthMismatch() throws {
        var connection = HTTP3Connection()
        let section = requestFieldSection(
            method: "POST", extra: [HeaderField(name: "content-length", value: "3")]
        )
        _ = try connection.receive(
            Self.stream, requestStream(section, body: Array("hello".utf8)), fin: true
        )
        #expect(resetStreamCode(&connection) == HTTP3ErrorCode.h3MessageError.rawValue)
    }

    @Test("DATA before HEADERS on a request stream is H3_FRAME_UNEXPECTED (§4.1)")
    func dataBeforeHeaders() {
        var connection = HTTP3Connection()
        #expect(
            errorCode(feeding: &connection, Self.stream, frame(.data, [0x01, 0x02]))
                == HTTP3ErrorCode.h3FrameUnexpected.rawValue)
    }

    @Test(
        "a control frame on a request stream is H3_FRAME_UNEXPECTED (§7.2)",
        arguments: [HTTP3FrameType.settings, .goAway, .cancelPush, .maxPushID, .pushPromise])
    func controlFrameOnRequestStream(_ type: HTTP3FrameType) {
        var connection = HTTP3Connection()
        #expect(
            errorCode(feeding: &connection, Self.stream, frame(type, [0x00]))
                == HTTP3ErrorCode.h3FrameUnexpected.rawValue)
    }

    @Test("an invalid QPACK static index is QPACK_DECOMPRESSION_FAILED (RFC 9204 §3.1)")
    func qpackDecompressionFailure() {
        var connection = HTTP3Connection()
        // Prefix 00 00 then an indexed static reference to index 99 (out of range): FF 24.
        let badSection: [UInt8] = [0x00, 0x00, 0xFF, 0x24]
        #expect(
            errorCode(feeding: &connection, Self.stream, frame(.headers, badSection), fin: true)
                == UInt64(QPACKError.Code.decompressionFailed.rawValue))
    }

    @Test("a frame whose length runs past the stream end is H3_FRAME_ERROR (§7.1)")
    func frameRunsPastStream() {
        var connection = HTTP3Connection()
        // HEADERS frame declaring length 10 but delivering only 3 octets, then FIN.
        let truncated: [UInt8] = [0x01, 0x0A, 0x00, 0x00, 0x51]
        #expect(
            errorCode(feeding: &connection, Self.stream, truncated, fin: true)
                == HTTP3ErrorCode.h3FrameError.rawValue)
    }

    // MARK: - Pseudo-header value validation & CONNECT (RFC 9114 §4.3.1 / §4.4)

    /// QPACK literal values decode as raw UTF-8 and may carry CR/LF/NUL; control bytes in
    /// :path/:authority/:scheme must be rejected (CWE-113/117), matching the HTTP/2 §8.3.1 screen.
    @Test(
        "a control byte in a pseudo-header value is H3_MESSAGE_ERROR (RFC 9114 §4.3.1)",
        arguments: [
            (name: ":path", value: "/a\r\nb"),
            (name: ":authority", value: "example.com\r\nx-evil: 1"),
            (name: ":scheme", value: "ht\r\ntps")
        ])
    func controlByteInPseudoHeaderIsMalformed(probe: (name: String, value: String)) throws {
        var fields = [
            HeaderField(name: ":method", value: "GET"),
            HeaderField(name: ":scheme", value: "https"),
            HeaderField(name: ":authority", value: "example.com"),
            HeaderField(name: ":path", value: "/")
        ]
        fields.removeAll { $0.name == probe.name }
        fields.append(HeaderField(name: probe.name, value: probe.value))
        var connection = HTTP3Connection()
        _ = try connection.receive(Self.stream, requestStream(fieldSection(fields)), fin: true)
        #expect(resetStreamCode(&connection) == HTTP3ErrorCode.h3MessageError.rawValue)
    }

    @Test("a standard CONNECT carrying :scheme or :path is H3_MESSAGE_ERROR (RFC 9114 §4.4)")
    func connectWithSchemeOrPathIsMalformed() throws {
        let fields = [
            HeaderField(name: ":method", value: "CONNECT"),
            HeaderField(name: ":authority", value: "example.com:443"),
            HeaderField(name: ":path", value: "/")
        ]
        var connection = HTTP3Connection()
        _ = try connection.receive(Self.stream, requestStream(fieldSection(fields)), fin: true)
        #expect(resetStreamCode(&connection) == HTTP3ErrorCode.h3MessageError.rawValue)
    }
}
