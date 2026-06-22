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

// MARK: - HTTP/2 fixtures (a DATA frame: length=8, type=0x0, flags=0, stream=1, + 8 payload octets)

let http2FrameHeaderBytes: [UInt8] = [0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]

let http2FrameBytes: [UInt8] =
    http2FrameHeaderBytes + [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]

// MARK: - Transport payload

let transportPayload = Array("ping-pong-loopback-throughput-probe".utf8)

// MARK: - WebSocket payload (≤125 octets, so the 7-bit length form applies; RFC 6455 §5.2)

let webSocketPayload = Array("the quick brown fox jumps over the lazy dog".utf8)
