//
//  Fixtures.swift
//  HTTPBenchmarks
//
//  Shared, immutable wire fixtures. Module-level `let`s are `Sendable` and built once.
//

import HPACK

// MARK: - HTTP/1.1 wire bytes

let requestLineBytes = Array("GET /index.html?q=swift HTTP/1.1\r\n".utf8)

let getRequestBytes = Array(
    ("GET /index.html?q=swift HTTP/1.1\r\n"
        + "Host: example.com\r\n"
        + "User-Agent: bench/1.0\r\n"
        + "Accept: text/html,application/json\r\n"
        + "Accept-Encoding: gzip, br\r\n"
        + "\r\n").utf8)

let headerBlockBytes = Array(
    ("Host: example.com\r\n"
        + "User-Agent: bench/1.0\r\n"
        + "Accept: text/html,application/json\r\n"
        + "Accept-Encoding: gzip, br\r\n"
        + "Cookie: session=abc123; theme=dark\r\n"
        + "\r\n").utf8)

let postBody = Array(#"{"hello":"world","n":123}"#.utf8)

let postRequestBytes: [UInt8] = {
    var bytes = Array(
        ("POST /submit HTTP/1.1\r\n"
            + "Host: example.com\r\n"
            + "Content-Type: application/json\r\n"
            + "Content-Length: \(postBody.count)\r\n"
            + "\r\n").utf8)
    bytes.append(contentsOf: postBody)
    return bytes
}()

let chunkedRequestBytes = Array(
    ("POST /upload HTTP/1.1\r\n"
        + "Host: example.com\r\n"
        + "Transfer-Encoding: chunked\r\n"
        + "\r\n"
        + "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n").utf8)

let chunkedBodyBytes = Array("1a\r\nabcdefghijklmnopqrstuvwxyz\r\n0\r\n\r\n".utf8)

/// A realistic browser GET (~11 header fields, long values) — the HTTP/1.1 server's real per-request
/// parse cost, unlike the tiny `getRequestBytes` above.
let realisticHTTP1Request = Array(
    ("GET /api/v1/items?page=2&sort=desc HTTP/1.1\r\n"
        + "Host: www.example.com\r\n"
        + "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 "
        + "Safari/605.1.15\r\n"
        + "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
        + "Accept-Encoding: gzip, deflate, br\r\n"
        + "Accept-Language: en-US,en;q=0.9\r\n"
        + "Cookie: session=8f3a2b1c9d4e5f6a7b8c; theme=dark; consent=granted\r\n"
        + "Referer: https://www.example.com/dashboard\r\n"
        + "Cache-Control: no-cache\r\n"
        + "Connection: keep-alive\r\n"
        + "\r\n").utf8)

// MARK: - Byte-class / token fixtures

let sampleFieldName = Array("Content-Type".utf8)
let sampleFieldValue = Array("text/html; charset=utf-8".utf8)

// MARK: - HPACK fixtures

let hpackFields = [
    HPACKField(name: ":method", value: "GET"),
    HPACKField(name: ":scheme", value: "https"),
    HPACKField(name: ":path", value: "/index.html"),
    HPACKField(name: ":authority", value: "example.com"),
    HPACKField(name: "user-agent", value: "bench/1.0"),
    HPACKField(name: "accept", value: "text/html,application/json"),
]

/// A realistic browser GET request (~12 fields with cookies / accept-* / user-agent) — a
/// representative header block for the steady-state HTTP/2 decode path, unlike the tiny set above.
let realisticRequestFields = [
    HPACKField(name: ":method", value: "GET"),
    HPACKField(name: ":scheme", value: "https"),
    HPACKField(name: ":authority", value: "www.example.com"),
    HPACKField(name: ":path", value: "/api/v1/items?page=2&sort=desc"),
    HPACKField(
        name: "user-agent",
        value: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Safari/605.1.15"),
    HPACKField(
        name: "accept", value: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    HPACKField(name: "accept-encoding", value: "gzip, deflate, br"),
    HPACKField(name: "accept-language", value: "en-US,en;q=0.9"),
    HPACKField(name: "cookie", value: "session=8f3a2b1c9d4e5f6a7b8c; theme=dark; consent=granted"),
    HPACKField(name: "referer", value: "https://www.example.com/dashboard"),
    HPACKField(name: "cache-control", value: "no-cache"),
    HPACKField(name: "pragma", value: "no-cache"),
]

/// A realistic JSON-API response header set — the server's encode side, mirroring the request set.
let realisticResponseFields = [
    HPACKField(name: ":status", value: "200"),
    HPACKField(name: "content-type", value: "application/json; charset=utf-8"),
    HPACKField(name: "content-length", value: "4096"),
    HPACKField(name: "server", value: "http-swift/0.1"),
    HPACKField(name: "date", value: "Sun, 22 Jun 2026 12:00:00 GMT"),
    HPACKField(name: "cache-control", value: "private, max-age=0"),
    HPACKField(name: "vary", value: "accept-encoding"),
    HPACKField(name: "x-request-id", value: "a1b2c3d4-e5f6-7890-abcd-ef0123456789"),
    HPACKField(name: "strict-transport-security", value: "max-age=31536000; includeSubDomains"),
]

// MARK: - HTTP/2 fixtures (a DATA frame: length=8, type=0x0, flags=0, stream=1, + 8 payload octets)

let http2FrameHeaderBytes: [UInt8] = [0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]

let http2FrameBytes: [UInt8] =
    http2FrameHeaderBytes + [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]

// MARK: - Transport payload

let transportPayload = Array("ping-pong-loopback-throughput-probe".utf8)

// MARK: - WebSocket payload (≤125 octets, so the 7-bit length form applies; RFC 6455 §5.2)

let webSocketPayload = Array("the quick brown fox jumps over the lazy dog".utf8)

/// A 4 KiB payload — exercises the 16-bit extended length form and the per-byte unmask loop at scale.
let webSocketLargePayload = [UInt8](repeating: 0x61, count: 4096)
