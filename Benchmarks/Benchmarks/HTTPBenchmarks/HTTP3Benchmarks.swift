//
//  HTTP3Benchmarks.swift
//  HTTPBenchmarks
//
//  HTTP/3 (RFC 9114) — the QUIC variable-length integer codec (RFC 9000 §16) that underlies every
//  frame type and length, plus the incremental frame decoder. The HTTP/3 mirror of HTTP2Benchmarks'
//  frame layer; frames are built with the public `QUICVarint` codec (the frame writer is internal).
//

import Benchmark
import HTTP3
import HTTPCore
import QPACK

func registerHTTP3Benchmarks() {
    // RFC 9000 §16 — encode a 4-octet varint (the form a typical frame length / large id takes).
    Benchmark("http3/Varint/encode") { benchmark in
        for _ in benchmark.scaledIterations {
            var output: [UInt8] = []
            QUICVarint.encode(151_288_809, into: &output)
            blackHole(output)
        }
    }

    Benchmark("http3/Varint/decode") { benchmark in
        var encoded: [UInt8] = []
        QUICVarint.encode(151_288_809, into: &encoded)
        for _ in benchmark.scaledIterations {
            encoded.withUnsafeBytes { raw in
                var reader = ByteReader(raw)
                blackHole(QUICVarint.decode(&reader))
            }
        }
    }

    // RFC 9114 §7.1 — pull one frame (varint type + varint length + payload) from a stream buffer.
    Benchmark("http3/FrameDecoder/nextFrame") { benchmark in
        for _ in benchmark.scaledIterations {
            http3DataFrame.withUnsafeBytes { raw in
                var reader = ByteReader(raw)
                let decoder = HTTP3FrameDecoder(maxFrameSize: 1 << 20)
                blackHole(try? decoder.nextFrame(&reader))
            }
        }
    }

    // The sans-I/O engine end-to-end: a request stream's HEADERS frame → a decoded request event
    // (frame decode, QPACK decode, §4 request mapping). The h3 request hot path — the mirror of
    // http2/Connection/receive-get, so the two protocols' per-request costs compare directly.
    Benchmark("http3/Connection/receive-get") { benchmark in
        for _ in benchmark.scaledIterations {
            var connection = HTTP3Connection()
            blackHole(connection.outbound())  // discard the queued control + QPACK stream opens
            blackHole(try? connection.receive(h3RequestStreamID, h3GetRequestWire, fin: true))
        }
    }

    // The request-body path: HEADERS + a DATA frame ending the stream with FIN (RFC 9114 §4.1).
    Benchmark("http3/Connection/receive-post") { benchmark in
        for _ in benchmark.scaledIterations {
            var connection = HTTP3Connection()
            blackHole(connection.outbound())
            blackHole(try? connection.receive(h3RequestStreamID, h3PostRequestWire, fin: true))
        }
    }

    // The response path: decode the request, then QPACK-encode + frame a HEADERS + DATA response.
    Benchmark("http3/Connection/respond") { benchmark in
        var fields = HTTPFields()
        fields.append("text/plain", for: .contentType)
        let response = HTTPResponse(status: .ok, headerFields: fields)
        let body = Array("Hello, HTTP/3!".utf8)
        for _ in benchmark.scaledIterations {
            var connection = HTTP3Connection()
            _ = connection.outbound()
            let events = try? connection.receive(h3RequestStreamID, h3GetRequestWire, fin: true)
            guard case .request(let streamID, _, _) = events?.first else { continue }
            try? connection.respond(to: streamID, response, body: body)
            blackHole(connection.outbound())
        }
    }
}

/// An HTTP/3 DATA frame (type 0x00) carrying a small payload, framed with the QUIC varint codec
/// (RFC 9000 §16) — the same construction the HTTP/3 server tests use.
private let http3DataFrame: [UInt8] = {
    var out: [UInt8] = []
    QUICVarint.encode(0x00, into: &out)  // DATA frame type
    let payload = Array("hello from a from-scratch HTTP/3 server".utf8)
    QUICVarint.encode(UInt64(payload.count), into: &out)
    out += payload
    return out
}()

/// A client-initiated bidirectional stream id (low bits `0b00`) — an HTTP/3 request stream (§6.1).
private let h3RequestStreamID = QUICStreamID(0)

/// Encodes one HTTP/3 frame (Type, Length, payload) with the public `QUICVarint` codec — the
/// engine's `HTTP3FrameWriter` is module-internal, so the benchmark re-implements the layout.
private func h3Frame(_ type: HTTP3FrameType, payload: [UInt8]) -> [UInt8] {
    var output: [UInt8] = []
    QUICVarint.encode(type.rawValue, into: &output)
    QUICVarint.encode(UInt64(payload.count), into: &output)
    output += payload
    return output
}

private let h3RequestFields: [HeaderField] = [
    HeaderField(name: ":method", value: "GET"),
    HeaderField(name: ":scheme", value: "https"),
    HeaderField(name: ":authority", value: "www.example.com"),
    HeaderField(name: ":path", value: "/api/v1/items?page=2&sort=desc"),
    HeaderField(name: "user-agent", value: "bench/1.0"),
    HeaderField(name: "accept", value: "text/html,application/json"),
    HeaderField(name: "accept-encoding", value: "gzip, deflate, br")
]

private let h3PostRequestFields: [HeaderField] = [
    HeaderField(name: ":method", value: "POST"),
    HeaderField(name: ":scheme", value: "https"),
    HeaderField(name: ":authority", value: "www.example.com"),
    HeaderField(name: ":path", value: "/submit"),
    HeaderField(name: "content-type", value: "application/json")
]

/// A GET request stream: a single HEADERS frame carrying the QPACK-encoded request field section.
private let h3GetRequestWire: [UInt8] =
    h3Frame(.headers, payload: QPACKEncoder().encode(h3RequestFields))

/// A POST request stream: HEADERS + a DATA frame carrying the body (an absent content-length is OK).
private let h3PostRequestWire: [UInt8] = {
    var wire = h3Frame(.headers, payload: QPACKEncoder().encode(h3PostRequestFields))
    wire += h3Frame(.data, payload: postBody)
    return wire
}()
