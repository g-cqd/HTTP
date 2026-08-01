//
//  QPACKBenchmarks.swift
//  HTTPBenchmarks
//
//  QPACK (RFC 9204) — the prefix-integer and string-literal codecs, the static-table lookup, a full
//  static-only field-section encode/decode round-trip, and the §3.2 dynamic-table structures. The
//  HTTP/3 mirror of HPACKBenchmarks.
//
//  The dynamic-table pair is deliberately run at two capacities. Absolute timings vary with the host,
//  but the SHAPE across the pair is the claim under test: a steady-state insert and an encoder lookup
//  are O(1), so a 16x larger table must cost the same, not 16x. Under the superseded newest-first
//  array both scaled with the table — insertion shifted every live entry, and the exact-match lookup
//  scanned all of them — and that capacity is chosen by the PEER via SETTINGS_QPACK_MAX_TABLE_CAPACITY.
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

    // RFC 9204 §3.2.2 — a STEADY-STATE insert: the table is already full, so each one evicts the
    // oldest entry and writes the newest. The table is warmed outside the loop so this measures the
    // recurring cost, not the one-off ring growth.
    for capacity in qpackTableCapacities {
        Benchmark("qpack/DynamicTable/insert-\(capacity / 1_024)k") { benchmark in
            var table = warmedQPACKTable(capacity: capacity)
            var counter = 0
            for _ in benchmark.scaledIterations {
                counter &+= 1
                table.insert(qpackTableEntry(counter))
                blackHole(table.count)
            }
        }
    }

    // RFC 9204 §3.2.4 / §4.5.4 — the encoder's exact and name lookups, the per-field cost of every
    // section it encodes against the dynamic table.
    for capacity in qpackTableCapacities {
        Benchmark("qpack/DynamicTable/lookup-\(capacity / 1_024)k") { benchmark in
            let table = warmedQPACKTable(capacity: capacity)
            // The newest live entry, and one never inserted (the encoder's novel-field path).
            let hit = qpackTableEntry(qpackWarmupInserts(capacity: capacity) - 1)
            let miss = qpackTableEntry(-1)
            for _ in benchmark.scaledIterations {
                blackHole(table.absoluteIndex(of: hit))
                blackHole(table.absoluteIndex(forName: hit.name))
                blackHole(table.absoluteIndex(of: miss))
            }
        }
    }
}

/// A realistic negotiated capacity and one 16x larger, so each dynamic-table benchmark reports a pair
/// whose ratio is the O(1) claim (RFC 9204 §3.2.3 `SETTINGS_QPACK_MAX_TABLE_CAPACITY`).
private let qpackTableCapacities = [4_096, 65_536]

/// A uniformly sized table entry: a fixed-width 10-octet name, empty value, plus the §3.2.1 constant.
private func qpackTableEntry(_ index: Int) -> HeaderField {
    var digits = String(index)
    while digits.count < 4 {
        digits = "0" + digits
    }
    return HeaderField(name: "field-" + digits, value: "")
}

/// How many inserts saturate a table of `capacity`, with margin so the ring reaches its high-water mark.
private func qpackWarmupInserts(capacity: Int) -> Int {
    (capacity / 42) * 3
}

/// A table churned well past its capacity — the state a long-lived HTTP/3 connection's encoder runs in.
private func warmedQPACKTable(capacity: Int) -> QPACKDynamicTable {
    var table = QPACKDynamicTable(capacity: capacity)
    for index in 0 ..< qpackWarmupInserts(capacity: capacity) {
        table.insert(qpackTableEntry(index))
    }
    return table
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
