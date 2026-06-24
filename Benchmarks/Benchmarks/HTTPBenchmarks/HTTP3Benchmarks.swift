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
