//
//  HTTP2StreamingServerTests.swift
//  HTTPServerTests
//
//  Native HTTP/2 response streaming end-to-end (P6b / RFC 9113 §8.1 / §6.9). Drives the server over a
//  ``ControllableConnection`` so a WINDOW_UPDATE is fed *only after* the producer has stalled on an
//  exhausted send window — the timing that proves the producer/serve-loop pump is deadlock-free and
//  bounded. The peer advertises a 5-octet stream window against a 50-octet streamed body, so the body
//  is released five octets at a time as the test grants window; the run completing (within the time
//  limit) and the full body arriving with END_STREAM is the assertion.
//

import HPACK
import HTTPCore
import HTTPTransport
import Testing

@testable import HTTPServer

@Suite("RFC 9113 §8.1 — native HTTP/2 server streaming (window stall)")
struct HTTP2StreamingServerTests {
    private static let preface = Array("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8)

    @Test(
        "a streamed response survives a forced window stall and arrives complete (no deadlock)",
        .timeLimit(.minutes(1)))
    func streamedResponseSurvivesWindowStall() async {
        let bodyByte: UInt8 = 0x5A
        let bodyLength = 50
        let responder = ClosureResponder { _, _, _ in
            .streaming(contentType: "application/octet-stream") { writer in
                try await writer.write([UInt8](repeating: bodyByte, count: bodyLength))
            }
        }
        let connection = ControllableConnection(alpn: "h2")
        let server = HTTPServer(transport: FakeTransport(), responder: responder)
        let serving = Task { await server.serve(connection) }

        // Open the connection with a tiny 5-octet stream window, then a GET on stream 1.
        await connection.feed(Self.preface + clientSettings(window: 5) + get(streamID: 1))

        // Wait until the server has opened stream 1 and emitted the first window-limited DATA — proof it
        // stalled on the exhausted window and parked on a read (the deadlock scenario). The cancellation
        // check lets the time limit end the run instead of spinning if the server never streams.
        while decodeData(await connection.sentBytes()).data.isEmpty, !Task.isCancelled {
            await Task.yield()
        }

        // Only now grant the window — five octets at a time, more than enough for the 50-octet body. A
        // grant past stream completion is harmless (the engine ignores a WINDOW_UPDATE on a closed
        // stream), so the body fully drains and the stream FINs.
        for _ in 0 ..< 14 {
            await connection.feed(windowUpdate(streamID: 1, increment: 5))
        }
        await connection.finishInbound()
        await serving.value

        let response = decodeData(await connection.sentBytes())
        #expect(response.data == [UInt8](repeating: bodyByte, count: bodyLength))
        #expect(response.finished)  // END_STREAM on the final DATA frame
    }

    // MARK: Wire helpers (raw RFC 9113 frames — no engine internals)

    private func frame(type: UInt8, flags: UInt8, streamID: UInt32, payload: [UInt8]) -> [UInt8] {
        var out: [UInt8] = [
            UInt8(payload.count >> 16 & 0xFF), UInt8(payload.count >> 8 & 0xFF),
            UInt8(payload.count & 0xFF), type, flags,
            UInt8(streamID >> 24 & 0xFF), UInt8(streamID >> 16 & 0xFF),
            UInt8(streamID >> 8 & 0xFF), UInt8(streamID & 0xFF)
        ]
        out += payload
        return out
    }

    private func clientSettings(window: UInt32) -> [UInt8] {
        frame(type: 0x04, flags: 0, streamID: 0, payload: [0x00, 0x04] + be32(window))
    }

    private func get(streamID: UInt32) -> [UInt8] {
        var encoder = HPACKEncoder(maxDynamicTableSize: 4_096)
        let block = encoder.encode([
            HPACKField(name: ":method", value: "GET"),
            HPACKField(name: ":scheme", value: "https"),
            HPACKField(name: ":path", value: "/"),
            HPACKField(name: ":authority", value: "example.com")
        ])
        // HEADERS with END_STREAM (0x01) | END_HEADERS (0x04).
        return frame(type: 0x01, flags: 0x05, streamID: streamID, payload: block)
    }

    private func windowUpdate(streamID: UInt32, increment: UInt32) -> [UInt8] {
        frame(type: 0x08, flags: 0, streamID: streamID, payload: be32(increment))
    }

    private func be32(_ value: UInt32) -> [UInt8] {
        [
            UInt8(value >> 24 & 0xFF), UInt8(value >> 16 & 0xFF),
            UInt8(value >> 8 & 0xFF), UInt8(value & 0xFF)
        ]
    }

    /// Concatenates the payload of every DATA frame and reports whether any carried END_STREAM.
    private func decodeData(_ bytes: [UInt8]) -> (data: [UInt8], finished: Bool) {
        var index = 0
        var data: [UInt8] = []
        var finished = false
        while index + 9 <= bytes.count {
            let length =
                Int(bytes[index]) << 16 | Int(bytes[index + 1]) << 8 | Int(bytes[index + 2])
            let type = bytes[index + 3]
            let flags = bytes[index + 4]
            let payloadStart = index + 9
            guard payloadStart + length <= bytes.count else {
                break
            }
            if type == 0x00 {  // DATA
                data += bytes[payloadStart ..< payloadStart + length]
                if flags & 0x01 != 0 { finished = true }
            }
            index = payloadStart + length
        }
        return (data, finished)
    }
}
