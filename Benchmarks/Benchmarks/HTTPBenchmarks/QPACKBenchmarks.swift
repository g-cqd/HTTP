//
//  QPACKBenchmarks.swift
//  HTTPBenchmarks
//
//  QPACK (RFC 9204) — the prefix-integer and string-literal codecs, the static-table lookup, and a
//  full static-only field-section encode/decode round-trip. The HTTP/3 mirror of HPACKBenchmarks; the
//  dynamic table is disabled in v1, so encode and decode are inherently the cold (literal) path.
//

import Benchmark
import HTTPCore
import QPACK

func registerQPACKBenchmarks() {
    Benchmark("qpack/Integer/encode") { benchmark in
        for _ in benchmark.scaledIterations {
            var output: [UInt8] = []
            QPACKInteger.encode(1_337, prefixBits: 5, into: &output)
            blackHole(output)
        }
    }

    Benchmark("qpack/Integer/decode") { benchmark in
        var encoded: [UInt8] = []
        QPACKInteger.encode(1_337, prefixBits: 5, into: &encoded)
        for _ in benchmark.scaledIterations {
            encoded.withUnsafeBytes { raw in
                var reader = ByteReader(raw)
                blackHole(QPACKInteger.decode(&reader, prefixBits: 5))
            }
        }
    }

    Benchmark("qpack/String/encode") { benchmark in
        for _ in benchmark.scaledIterations {
            var output: [UInt8] = []
            QPACKString.encode(sampleFieldValue, prefixBits: 7, into: &output)
            blackHole(output)
        }
    }

    // RFC 9204 App. A — the O(1) static-table index lookup (first and last of the 99 entries).
    Benchmark("qpack/StaticTable/lookup") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(QPACKStaticTable.field(at: 0))  // :authority
            blackHole(QPACKStaticTable.field(at: QPACKStaticTable.count - 1))  // last static entry
        }
    }

    // A realistic request field section, encoded static-only (RFC 9204 §4.5): the server's per-request
    // decode input and the client's encode output, both literal (no dynamic table in v1).
    Benchmark("qpack/fieldSection/encode") { benchmark in
        let encoder = QPACKEncoder()
        for _ in benchmark.scaledIterations {
            blackHole(encoder.encode(qpackRequestFields))
        }
    }

    Benchmark("qpack/fieldSection/decode") { benchmark in
        let block = QPACKEncoder().encode(qpackRequestFields)
        for _ in benchmark.scaledIterations {
            block.withUnsafeBytes { raw in
                let decoder = QPACKDecoder()
                blackHole(try? decoder.decode(raw.bytes))
            }
        }
    }
}

/// A realistic browser request as a QPACK field section (RFC 9204) — the static-only analog of the
/// HPACK `realisticRequestFields`, expressed as the shared `HeaderField` currency type.
private let qpackRequestFields: [HeaderField] = [
    HeaderField(name: ":method", value: "GET"),
    HeaderField(name: ":scheme", value: "https"),
    HeaderField(name: ":authority", value: "www.example.com"),
    HeaderField(name: ":path", value: "/index.html"),
    HeaderField(name: "user-agent", value: "Mozilla/5.0 (Macintosh; Apple Silicon)"),
    HeaderField(name: "accept", value: "text/html,application/xhtml+xml,application/xml;q=0.9"),
    HeaderField(name: "accept-language", value: "en-US,en;q=0.9"),
    HeaderField(name: "accept-encoding", value: "gzip, deflate, br")
]
