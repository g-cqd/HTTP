//
//  CVEHardeningTests.swift
//  HTTPServerTests
//
//  Regression suite pinned to the 10-year HTTP/TLS/Cache CVE audit (2016–2026):
//  - HTTP/1.1 Host-header syntax validation (RFC 9110 §7.2 — userinfo `@`, path `/`, whitespace,
//    port > 65535, malformed IPv6)
//  - HTTP/2 unsolicited PING-ACK flood, GOAWAY flood & malformed GOAWAY (< 8 B), and unknown-frame
//    flood (CVE-2019-9512 / CVE-2019-9518 class)
//  - Shared CacheMiddleware RFC 9111 §3.5: never store responses to `Authorization` requests or
//    `Set-Cookie` responses unless explicitly permitted (`public` / `s-maxage` / `must-revalidate`)
//

import HTTP1
import HTTP3
import HTTPCore
import HTTPServer
import HTTPTestSupport
import Synchronization
import Testing

@testable import HTTP2

@Suite("10-Year CVE Hardening Regressions (Host, HTTP/2 Floods, Shared Cache)")
struct CVEHardeningTests {
    // MARK: - HTTP/1.1 Host-Header Injection (RFC 9110 §7.2)

    @Test("rejects syntactically invalid HTTP/1.1 Host headers (userinfo, path, spaces, bad port)")
    func rejectsMalformedHostHeaders() {
        let malformedHosts = [
            "evil.com@good.com",
            "example.com/injected",
            "example.com?q=1",
            "example.com#frag",
            "example.com evil.com",
            "example.com:99999",
            "example.com:abc",
            "example.com:80:443",
            "[::1",
            "[::1]extra",
            ":8080"
        ]
        for host in malformedHosts {
            let wire = Array("GET / HTTP/1.1\r\nHost: \(host)\r\n\r\n".utf8)
            #expect(throws: HTTP1ParseError.invalidHost, "expected invalidHost for Host: \(host)") {
                try wire.withUnsafeBytes { raw in
                    var reader = ByteReader(raw)
                    _ = try RequestParser.parse(&reader, limits: .default)
                }
            }
        }
    }

    @Test("accepts valid HTTP/1.1 Host headers (reg-name, IPv4, IPv6, optional port)")
    func acceptsValidHostHeaders() throws {
        let validHosts = [
            "example.com",
            "example.com:8080",
            "127.0.0.1:443",
            "[::1]",
            "[2001:db8::1]:8443",
            ""
        ]
        for host in validHosts {
            let wire = Array("GET / HTTP/1.1\r\nHost: \(host)\r\n\r\n".utf8)
            let parsed = try wire.withUnsafeBytes { raw in
                var reader = ByteReader(raw)
                return try RequestParser.parse(&reader, limits: .default)
            }
            #expect(parsed.request.authority == host)
        }
    }

    @Test(
        "rejects HTTP/1.1 absolute-form request-target whose authority mismatches Host (RFC 9112 §3.2.2)"
    )
    func rejectsAbsoluteTargetHostMismatch() throws {
        let mismatches = [
            ("GET http://evil.com/admin HTTP/1.1\r\nHost: good.com\r\n\r\n"),
            ("GET https://good.com:8443/a HTTP/1.1\r\nHost: good.com\r\n\r\n"),
            ("GET http://user@good.com/a HTTP/1.1\r\nHost: good.com\r\n\r\n")
        ]
        for rawReq in mismatches {
            let wire = Array(rawReq.utf8)
            #expect(throws: HTTP1ParseError.invalidHost, "expected invalidHost for \(rawReq)") {
                try wire.withUnsafeBytes { raw in
                    var reader = ByteReader(raw)
                    _ = try RequestParser.parse(&reader, limits: .default)
                }
            }
        }
        // Matching absolute-form (case-insensitive) succeeds.
        let matching = Array(
            "GET http://Example.COM:8080/ok?x=1 HTTP/1.1\r\nHost: example.com:8080\r\n\r\n".utf8
        )
        let parsed = try matching.withUnsafeBytes { raw in
            var reader = ByteReader(raw)
            return try RequestParser.parse(&reader, limits: .default)
        }
        #expect(parsed.request.authority == "example.com:8080")
    }

    @Test(
        "HTTP/3 control-stream GREASE/unknown frame flood closes connection with H3_EXCESSIVE_LOAD")
    func rejectsHTTP3ControlFrameFlood() {
        let limits = HTTPLimits(maxControlFramesPerInterval: 5)
        var conn = HTTP3Connection(limits: limits)
        _ = conn.outbound()  // drain initial server control/QPACK opens
        // Client control stream (uni stream 2): type 0x00, SETTINGS (type 0x04, len 0x00),
        // then 10 GREASE/unknown frames (type 0x21 = 33, len 0x00).
        var payload: [UInt8] = [0x00, 0x04, 0x00]
        for _ in 0 ..< 10 {
            payload.append(contentsOf: [0x21, 0x00])
        }
        #expect(throws: HTTP3Error.self) {
            _ = try conn.receive(QUICStreamID(2), payload, fin: false)
        }
        let actions = conn.outbound()
        let closed = actions.contains {
            if case .closeConnection(let code) = $0 {
                return code == HTTP3ErrorCode.h3ExcessiveLoad.rawValue
            }
            return false
        }
        #expect(closed)
    }

    // MARK: - HTTP/2 Unsolicited PING-ACK, GOAWAY & Unknown-Frame Floods

    @Test("HTTP/2 rejects unsolicited PING-ACK flood with ENHANCE_YOUR_CALM")
    func rejectsPingAckFlood() throws {
        let limits = HTTPLimits(maxControlFramesPerInterval: 5)
        var conn = HTTP2Connection(limits: limits)
        var wire = HTTP2ConnectionPreface.client
        var writer = HTTP2FrameWriter()
        let opaque = [UInt8](repeating: 0xAA, count: 8)
        for _ in 0 ..< 10 {
            writer.writeFrame(.ping, flags: .ack, payload: opaque)
        }
        wire.append(contentsOf: writer.drain())

        #expect(throws: HTTP2Error.self) {
            _ = try conn.receive(wire)
        }
    }

    @Test("HTTP/2 rejects unknown-frame-type flood with ENHANCE_YOUR_CALM")
    func rejectsUnknownFrameFlood() throws {
        let limits = HTTPLimits(maxControlFramesPerInterval: 5)
        var conn = HTTP2Connection(limits: limits)
        var wire = HTTP2ConnectionPreface.client
        // Raw 9-byte frame header for unknown type 0xFE, length 0, flags 0, stream 0.
        let unknownFrame: [UInt8] = [0x00, 0x00, 0x00, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00]
        for _ in 0 ..< 10 {
            wire.append(contentsOf: unknownFrame)
        }
        #expect(throws: HTTP2Error.self) {
            _ = try conn.receive(wire)
        }
    }

    @Test("HTTP/2 rejects malformed GOAWAY shorter than 8 octets")
    func rejectsShortGoAway() throws {
        var conn = HTTP2Connection()
        var wire = HTTP2ConnectionPreface.client
        var writer = HTTP2FrameWriter()
        writer.writeFrame(.goAway, payload: [0x00, 0x00, 0x00, 0x01])
        wire.append(contentsOf: writer.drain())
        #expect(throws: HTTP2Error.self) {
            _ = try conn.receive(wire)
        }
    }

    // MARK: - Shared Cache RFC 9111 §3.5 (Authorization & Set-Cookie Isolation)

    @Test(
        "CacheMiddleware does not store responses to Authorization requests without public/s-maxage"
    )
    func cacheRefusesAuthenticatedResponsesByDefault() async {
        let middleware = CacheMiddleware { 1_000 }
        let calls = Mutex(0)
        let responder = ClosureResponder { _, _, _ in
            let count = calls.withLock { current -> Int in
                current += 1
                return current
            }
            var fields = HTTPFields()
            _ = fields.setValue("max-age=60", for: .cacheControl)
            return ServerResponse(
                HTTPResponse(status: .ok, headerFields: fields),
                body: Array("secret-\(count)".utf8)
            )
        }

        var authFields = HTTPFields()
        _ = authFields.setValue("Bearer user-token", for: .authorization)
        let req = HTTPRequest(
            method: .get, authority: "example.com", path: "/me", headerFields: authFields
        )

        let r1 = await middleware.respond(to: req, body: [], next: responder)
        let r2 = await middleware.respond(to: req, body: [], next: responder)
        #expect(r1.body != r2.body)
        #expect(calls.withLock(\.self) == 2)
    }

    @Test("CacheMiddleware does not store Set-Cookie responses unless explicitly marked public")
    func cacheRefusesSetCookieResponsesByDefault() async {
        let middleware = CacheMiddleware { 1_000 }
        let calls = Mutex(0)
        let responder = ClosureResponder { _, _, _ in
            let count = calls.withLock { current -> Int in
                current += 1
                return current
            }
            var fields = HTTPFields()
            _ = fields.setValue("max-age=60", for: .cacheControl)
            _ = fields.setValue("sid=token-\(count); HttpOnly; Secure", for: .setCookie)
            return ServerResponse(
                HTTPResponse(status: .ok, headerFields: fields),
                body: Array("ok-\(count)".utf8)
            )
        }

        let req = HTTPRequest(method: .get, authority: "example.com", path: "/login")
        let r1 = await middleware.respond(to: req, body: [], next: responder)
        let r2 = await middleware.respond(to: req, body: [], next: responder)
        #expect(r1.body != r2.body)
        #expect(calls.withLock(\.self) == 2)
    }
}
