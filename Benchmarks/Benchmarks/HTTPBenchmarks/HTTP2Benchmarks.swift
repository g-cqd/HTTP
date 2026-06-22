//
//  HTTP2Benchmarks.swift
//  HTTPBenchmarks
//
//  HTTP/2 (RFC 9113) — the 9-octet frame-header parse and the incremental frame decoder.
//

import Benchmark
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
}
