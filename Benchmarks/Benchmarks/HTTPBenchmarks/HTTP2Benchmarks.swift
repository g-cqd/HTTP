//
//  HTTP2Benchmarks.swift
//  HTTPBenchmarks
//
//  HTTP/2 (RFC 9113) — the 9-octet frame-header parse and the incremental frame decoder.
//

import Benchmark
import HPACK
import HTTP2
import HTTPCore

func registerHTTP2Benchmarks() {
    Benchmark("http2/FrameHeader/parse") { benchmark in
        for _ in benchmark.scaledIterations {
            http2FrameHeaderBytes.withUnsafeBytes { raw in
                var reader = ByteReader(raw)
                blackHole(HTTP2FrameHeader.parse(&reader))
            }
        }
    }

    Benchmark("http2/FrameDecoder/nextFrame") { benchmark in
        let decoder = HTTP2FrameDecoder()
        for _ in benchmark.scaledIterations {
            http2FrameBytes.withUnsafeBytes { raw in
                var reader = ByteReader(raw)
                blackHole(try? decoder.nextFrame(&reader))
            }
        }
    }

    // The sans-I/O engine end-to-end: preface + SETTINGS + HEADERS(GET) → a decoded request event
    // (preface match, frame decode, HEADERS assembly, HPACK decode, §8.3 request mapping).
    Benchmark("http2/Connection/receive-get") { benchmark in
        let wire = clientGetWire()
        for _ in benchmark.scaledIterations {
            var connection = HTTP2Connection()
            blackHole(connection.outboundBytes())  // discard the queued server SETTINGS preface
            blackHole(try? connection.receive(wire))
        }
    }

    // The response path: decode the request, then HPACK-encode + frame a HEADERS + DATA response.
    Benchmark("http2/Connection/respond") { benchmark in
        let wire = clientGetWire()
        var fields = HTTPFields()
        fields.append("text/plain", for: .contentType)
        let response = HTTPResponse(status: .ok, headerFields: fields)
        let body = Array("Hello, HTTP/2!".utf8)
        for _ in benchmark.scaledIterations {
            var connection = HTTP2Connection()
            _ = connection.outboundBytes()
            guard let events = try? connection.receive(wire),
                case .request(let streamID, _, _) = events.first
            else { continue }
            try? connection.respond(to: streamID, response, body: body)
            blackHole(connection.outboundBytes())
        }
    }

    // The DATA path + inbound flow control: preface + SETTINGS + HEADERS(POST) + DATA(END_STREAM) →
    // a request event, the connection debiting its receive window and queuing any WINDOW_UPDATE.
    Benchmark("http2/Connection/receive-post") { benchmark in
        let wire = clientPostWire(body: postBody)
        for _ in benchmark.scaledIterations {
            var connection = HTTP2Connection()
            blackHole(connection.outboundBytes())  // discard the queued server SETTINGS preface
            blackHole(try? connection.receive(wire))
        }
    }
}

/// Builds one client wire — connection preface + an empty SETTINGS frame + a HEADERS frame carrying
/// a GET request — to drive the ``HTTP2Connection`` engine benchmarks.
private func clientGetWire() -> [UInt8] {
    var encoder = HPACKEncoder(maxDynamicTableSize: 4_096)
    let block = encoder.encode([
        HPACKField(name: ":method", value: "GET"),
        HPACKField(name: ":scheme", value: "https"),
        HPACKField(name: ":path", value: "/index.html"),
        HPACKField(name: ":authority", value: "example.com")
    ])
    var settings: [UInt8] = []
    HTTP2FrameHeader(payloadLength: 0, type: .settings, streamID: .connection)
        .encode(into: &settings)
    var headers: [UInt8] = []
    HTTP2FrameHeader(
        payloadLength: block.count, type: .headers, flags: [.endHeaders, .endStream],
        streamID: HTTP2StreamID(1)
    )
    .encode(into: &headers)
    headers.append(contentsOf: block)
    return HTTP2ConnectionPreface.client + settings + headers
}

/// Builds one client wire — preface + SETTINGS + HEADERS(POST, no END_STREAM) + a DATA frame with
/// END_STREAM — to drive the engine's request-body + inbound-flow-control path.
private func clientPostWire(body: [UInt8]) -> [UInt8] {
    var encoder = HPACKEncoder(maxDynamicTableSize: 4_096)
    let block = encoder.encode([
        HPACKField(name: ":method", value: "POST"),
        HPACKField(name: ":scheme", value: "https"),
        HPACKField(name: ":path", value: "/submit"),
        HPACKField(name: ":authority", value: "example.com")
    ])
    var settings: [UInt8] = []
    HTTP2FrameHeader(payloadLength: 0, type: .settings, streamID: .connection)
        .encode(into: &settings)
    var headers: [UInt8] = []
    HTTP2FrameHeader(
        payloadLength: block.count, type: .headers, flags: [.endHeaders], streamID: HTTP2StreamID(1)
    )
    .encode(into: &headers)
    headers.append(contentsOf: block)
    var data: [UInt8] = []
    HTTP2FrameHeader(
        payloadLength: body.count, type: .data, flags: [.endStream], streamID: HTTP2StreamID(1)
    )
    .encode(into: &data)
    data.append(contentsOf: body)
    return HTTP2ConnectionPreface.client + settings + headers + data
}
