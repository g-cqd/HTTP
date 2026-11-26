//
//  HTTPClientURLTests.swift
//  HTTPClientTests
//
//  Sans-I/O: RFC 3986 URL splitting / redirect resolution, RFC 9110 origin parsing, and RFC 9110 §8.4
//  content decoding under the decompression-bomb bound.
//

import HTTPDeflate
import HTTPZstd
import Testing

@testable import HTTPClient

@Suite("HTTPClient — URL, origin, and content-coding units")
struct HTTPClientURLTests {
    @Test("splits absolute URLs into scheme, authority, and origin-form target; drops fragments")
    func splitsAbsoluteURLs() throws {
        let url = try HTTPClientURL(
            "https://developer.apple.com/tutorials/data/documentation/swiftui.json?x=1#top"
        )
        #expect(url.scheme == "https" && url.authority == "developer.apple.com")
        #expect(url.path == "/tutorials/data/documentation/swiftui.json?x=1")
        #expect(try HTTPClientURL("http://example.com").path == "/")
        #expect(try HTTPClientURL("http://example.com?q").path == "/?q")
        #expect(throws: HTTPClientError.self) { try HTTPClientURL("ftp://example.com/") }
        #expect(throws: HTTPClientError.self) { try HTTPClientURL("https://user@example.com/") }
        #expect(throws: HTTPClientError.self) { try HTTPClientURL("https://example.com/a b") }
        #expect(throws: HTTPClientError.self) { try HTTPClientURL("https://example.com/a\r\nX: 1") }
    }

    @Test("parses origins with default ports, explicit ports, and IPv6 literals")
    func parsesOrigins() throws {
        let https = try HTTPOrigin(scheme: "https", authority: "Developer.Apple.com")
        #expect(
            https.host == "developer.apple.com" && https.port == 443
                && https.hostHeader == "developer.apple.com")
        let http = try HTTPOrigin(scheme: "http", authority: "127.0.0.1:8080")
        #expect(http.port == 8_080 && http.hostHeader == "127.0.0.1:8080")
        let v6 = try HTTPOrigin(scheme: "https", authority: "[::1]:8443")
        #expect(v6.host == "::1" && v6.port == 8_443 && v6.hostHeader == "[::1]:8443")
        #expect(throws: HTTPClientError.self) {
            try HTTPOrigin(scheme: "https", authority: "host:0")
        }
        #expect(throws: HTTPClientError.self) {
            try HTTPOrigin(scheme: "https", authority: "host:99999")
        }
    }

    @Test("resolves absolute, network-path, absolute-path, and relative redirect locations")
    func resolvesRedirects() throws {
        let origin = try HTTPOrigin(scheme: "https", authority: "a.example")
        #expect(
            try HTTPClientURL("https://b.example/x", relativeTo: origin, path: "/p/q").authority
                == "b.example")
        #expect(
            try HTTPClientURL("//c.example/y", relativeTo: origin, path: "/p/q").authority
                == "c.example")
        #expect(try HTTPClientURL("/z?1", relativeTo: origin, path: "/p/q").path == "/z?1")
        #expect(try HTTPClientURL("r", relativeTo: origin, path: "/p/q?s").path == "/p/r")
    }

    @Test(
        "decodes zstd, gzip, and deflate bodies and fails closed past the bound or on unknown codings"
    )
    func decodesContentCodings() throws {
        let plain = Array(String(repeating: "apple-docs ", count: 2_000).utf8)
        let zstd = try Zstd.compress(plain)
        #expect(try ContentCodings.decode(zstd, encodings: ["zstd"], maxOutput: 1 << 20) == plain)
        let gzip = DeflateCodec.gzip(plain)
        #expect(try ContentCodings.decode(gzip, encodings: ["x-gzip"], maxOutput: 1 << 20) == plain)
        #expect(
            try ContentCodings.decode(plain, encodings: ["identity"], maxOutput: 1 << 20) == plain
        )
        #expect(throws: HTTPClientError.self) {
            try ContentCodings.decode(gzip, encodings: ["gzip"], maxOutput: 1_000)
        }
        #expect(throws: HTTPClientError.self) {
            try ContentCodings.decode(plain, encodings: ["br"], maxOutput: 1 << 20)
        }
        #expect(throws: HTTPClientError.self) {
            try ContentCodings.decode(plain, encodings: ["gzip, gzip, gzip"], maxOutput: 1 << 20)
        }
        #expect(ContentCodings.tokens(" Keep-Alive ,close") == ["keep-alive", "close"])
    }
}
