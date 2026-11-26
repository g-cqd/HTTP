//
//  ResponseParserTests.swift
//  HTTP1Tests
//
//  RED→GREEN driver for RFC 9112 §3 / §4 / §6 HTTP/1.1 client request serialization and response
//  parsing (status-line, headers, Content-Length, chunked, HEAD / 204 / 304 no-body framing, and
//  close-delimited EOF bodies).
//

import HTTPCore
import Testing

@testable import HTTP1

@Suite("RFC 9112 §3/§4/§6 — client request serialization & response parsing")
struct ResponseParserTests {
    private func parseHead(
        _ wire: String,
        forRequestMethod method: HTTPMethod = .get,
        limits: HTTPLimits = .default
    ) throws -> ResponseHead {
        let bytes = Array(wire.utf8)
        return try bytes.withUnsafeBytes { raw in
            var reader = ByteReader(raw)
            return try ResponseParser.parseHead(&reader, forRequestMethod: method, limits: limits)
        }
    }

    @Test(
        "RequestSerializer emits request-line, Host from authority, and Content-Length on non-empty body"
    )
    func serializesClientRequests() throws {
        var fields = HTTPFields()
        fields.append("application/json", for: .accept)
        let getReq = HTTPRequest(
            method: .get,
            scheme: "https",
            authority: "developer.apple.com",
            path: "/tutorials/data/documentation/swiftui.json",
            headerFields: fields
        )
        let getWire = String(validating: try RequestSerializer.serialize(getReq), as: UTF8.self)
        #expect(
            getWire == "GET /tutorials/data/documentation/swiftui.json HTTP/1.1\r\n"
                + "host: developer.apple.com\r\n"
                + "accept: application/json\r\n\r\n"
        )

        let postReq = HTTPRequest(method: .post, authority: "api.example.com", path: "/items")
        let postWire = String(
            validating: try RequestSerializer.serialize(postReq, body: Array("hello".utf8)),
            as: UTF8.self
        )
        #expect(
            postWire
                == "POST /items HTTP/1.1\r\nhost: api.example.com\r\ncontent-length: 5\r\n\r\nhello"
        )
    }

    @Test("RequestSerializer rejects CR/LF/whitespace in path or invalid Host (RFC 9112 §3.2)")
    func rejectsSmuggledRequestComponents() {
        let injectedPath = HTTPRequest(method: .get, authority: "example.com", path: "/a\r\nX: 1")
        #expect(throws: HTTP1ParseError.invalidTarget) {
            _ = try RequestSerializer.serialize(injectedPath)
        }
        let missingHost = HTTPRequest(method: .get, path: "/ok")
        #expect(throws: HTTP1ParseError.invalidHost) {
            _ = try RequestSerializer.serialize(missingHost)
        }
    }

    @Test("parses status-line with and without reason-phrase and Content-Length framing")
    func parsesStatusLineAndContentLength() throws {
        let head = try parseHead(
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nETag: \"abc\"\r\n\r\nhello"
        )
        #expect(head.version == .http11)
        #expect(head.response.status == .ok)
        #expect(head.response.headerFields[.etag] == "\"abc\"")
        #expect(head.framing == .contentLength(5))

        let emptyReason = try parseHead("HTTP/1.1 200 \r\nContent-Length: 0\r\n\r\n")
        #expect(emptyReason.response.status == .ok)
        #expect(emptyReason.framing == .contentLength(0))
    }

    @Test(
        "HEAD, 1xx, 204, and 304 responses resolve to .none framing even when Content-Length is present (RFC 9112 §6.3)"
    )
    func headAndBodylessStatusesHaveNoBody() throws {
        let headResp = try parseHead(
            "HTTP/1.1 200 OK\r\nContent-Length: 9999\r\n\r\n",
            forRequestMethod: .head
        )
        #expect(headResp.framing == .none)

        for code in [100, 204, 304] {
            let h = try parseHead("HTTP/1.1 \(code) Notice\r\nContent-Length: 42\r\n\r\n")
            #expect(h.framing == .none)
        }
    }

    @Test(
        "chunked and close-delimited responses resolve their RFC 9112 §6.3 framing and reject CL+TE"
    )
    func chunkedCloseDelimitedAndSmugglingRejection() throws {
        let chunked = try parseHead("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
        #expect(chunked.framing == .chunked)

        let untilEOF = try parseHead("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n")
        #expect(untilEOF.framing == .untilEOF)

        #expect(throws: HTTP1ParseError.contentLengthWithTransferEncoding) {
            _ = try parseHead(
                "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n"
            )
        }
    }

    @Test("rejects malformed status lines and out-of-range status codes (RFC 9112 §4)")
    func rejectsMalformedStatusLines() {
        for bad in [
            "HTTP/1.1 200\r\n\r\n",
            "HTTP/1.1 999 Custom\r\n\r\n",
            "HTTP/1.1 20A OK\r\n\r\n",
            "HTTP/2.0 200 OK\r\n\r\n",
            "200 OK\r\n\r\n"
        ] {
            #expect(throws: HTTP1ParseError.self) {
                _ = try parseHead(bad)
            }
        }
    }
}
