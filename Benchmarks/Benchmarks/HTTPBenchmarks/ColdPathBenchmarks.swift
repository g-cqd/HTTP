//
//  ColdPathBenchmarks.swift
//  HTTPBenchmarks
//
//  Cold paths — the reject / error branches the hot-path suites never exercise. Measuring them guards
//  against a cheap-to-send malformed input becoming disproportionately expensive to reject (a CPU
//  amplification vector), and rounds out the "hot AND cold path" coverage.
//

import Benchmark
import HPACK
import HTTP1
import HTTP2
import HTTPCore

func registerColdPathBenchmarks() {
    // A well-formed head that fails the mandatory-Host check (RFC 9110 §7.2): the parser walks the
    // whole request line + header section before rejecting — the cost of a cheap invalid request.
    Benchmark("cold/http1/missing-host") { benchmark in
        let bytes = Array("GET /a/b/c?q=1 HTTP/1.1\r\nAccept: */*\r\nUser-Agent: x\r\n\r\n".utf8)
        for _ in benchmark.scaledIterations {
            bytes.withUnsafeBytes { raw in
                var reader = ByteReader(raw)
                blackHole(try? RequestParser.parse(&reader, limits: .default))
            }
        }
    }

    // A frame header declaring a payload larger than SETTINGS_MAX_FRAME_SIZE (RFC 9113 §4.2): the
    // decoder must reject with FRAME_SIZE_ERROR from the header alone, never buffering the claim.
    Benchmark("cold/http2/oversized-frame") { benchmark in
        // A DATA frame on stream 1 whose 3-octet length field declares 65536 octets of payload.
        let header: [UInt8] = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
        for _ in benchmark.scaledIterations {
            header.withUnsafeBytes { raw in
                var reader = ByteReader(raw)
                let decoder = HTTP2FrameDecoder()  // default maxFrameSize 16384
                blackHole(try? decoder.nextFrame(&reader))
            }
        }
    }

    // An indexed field referencing index 63 with an empty dynamic table (RFC 7541 §2.3.3): the decoder
    // must reject with an invalid-index error rather than read past the static table.
    Benchmark("cold/hpack/invalid-index") { benchmark in
        let block: [UInt8] = [0xBF]  // indexed field, index 63 — out of range, dynamic table empty
        for _ in benchmark.scaledIterations {
            block.withUnsafeBytes { raw in
                var decoder = HPACKDecoder(maxDynamicTableSize: 4_096)
                blackHole(try? decoder.decode(raw.bytes))
            }
        }
    }
}
