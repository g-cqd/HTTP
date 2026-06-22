//
//  HPACKBenchmarks.swift
//  HTTPBenchmarks
//
//  HPACK (RFC 7541) — the prefix-integer and string-literal codecs, plus a full header-block
//  encode/decode round-trip against a fresh dynamic table.
//

import Benchmark
import HPACK
import HTTPCore

func registerHPACKBenchmarks() {
    Benchmark("hpack/Integer/encode") { benchmark in
        for _ in benchmark.scaledIterations {
            var output = [UInt8]()
            HPACKInteger.encode(1337, prefixBits: 5, into: &output)
            blackHole(output)
        }
    }

    Benchmark("hpack/Integer/decode") { benchmark in
        var encoded = [UInt8]()
        HPACKInteger.encode(1337, prefixBits: 5, into: &encoded)
        for _ in benchmark.scaledIterations {
            encoded.withUnsafeBytes { raw in
                var reader = ByteReader(raw)
                blackHole(try? HPACKInteger.decode(&reader, prefixBits: 5))
            }
        }
    }

    Benchmark("hpack/String/encode") { benchmark in
        for _ in benchmark.scaledIterations {
            var output = [UInt8]()
            HPACKString.encode(sampleFieldValue, into: &output)
            blackHole(output)
        }
    }

    Benchmark("hpack/headerBlock/encode") { benchmark in
        for _ in benchmark.scaledIterations {
            var encoder = HPACKEncoder(maxDynamicTableSize: 4096)
            blackHole(encoder.encode(hpackFields))
        }
    }

    Benchmark("hpack/headerBlock/decode") { benchmark in
        var seed = HPACKEncoder(maxDynamicTableSize: 4096)
        let block = seed.encode(hpackFields)
        for _ in benchmark.scaledIterations {
            block.withUnsafeBytes { raw in
                var decoder = HPACKDecoder(maxDynamicTableSize: 4096)
                blackHole(try? decoder.decode(raw.bytes))
            }
        }
    }

    // RFC 7541 §2.3.2 — newest-first insertion into the dynamic table (the FIFO eviction store).
    Benchmark("hpack/DynamicTable/add") { benchmark in
        for _ in benchmark.scaledIterations {
            var table = HPACKDynamicTable(maxSize: 4096)
            for field in hpackFields { table.add(field) }
            blackHole(table)
        }
    }

    // RFC 7541 App. A — the O(1) static-table index lookup (first and last entries).
    Benchmark("hpack/StaticTable/lookup") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(HPACKStaticTable.field(at: 2))  // :method GET
            blackHole(HPACKStaticTable.field(at: HPACKStaticTable.count))  // last static entry
        }
    }
}
