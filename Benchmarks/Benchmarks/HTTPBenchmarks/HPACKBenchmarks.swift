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
            var output: [UInt8] = []
            HPACKInteger.encode(1_337, prefixBits: 5, into: &output)
            blackHole(output)
        }
    }

    Benchmark("hpack/Integer/decode") { benchmark in
        var encoded: [UInt8] = []
        HPACKInteger.encode(1_337, prefixBits: 5, into: &encoded)
        for _ in benchmark.scaledIterations {
            encoded.withUnsafeBytes { raw in
                var reader = ByteReader(raw)
                blackHole(try? HPACKInteger.decode(&reader, prefixBits: 5))
            }
        }
    }

    registerHPACKStringBenchmarks()

    Benchmark("hpack/headerBlock/encode") { benchmark in
        for _ in benchmark.scaledIterations {
            var encoder = HPACKEncoder(maxDynamicTableSize: 4_096)
            blackHole(encoder.encode(hpackFields))
        }
    }

    Benchmark("hpack/headerBlock/decode") { benchmark in
        var seed = HPACKEncoder(maxDynamicTableSize: 4_096)
        let block = seed.encode(hpackFields)
        for _ in benchmark.scaledIterations {
            block.withUnsafeBytes { raw in
                var decoder = HPACKDecoder(maxDynamicTableSize: 4_096)
                blackHole(try? decoder.decode(raw.bytes))
            }
        }
    }

    // RFC 7541 §2.3.2 — newest-first insertion into the dynamic table (the FIFO eviction store).
    Benchmark("hpack/DynamicTable/add") { benchmark in
        for _ in benchmark.scaledIterations {
            var table = HPACKDynamicTable(maxSize: 4_096)
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

    // A realistic browser request on a *fresh* connection — the first request, decoded with a cold
    // dynamic table (literals + incremental indexing, one String per field). The cold-start cost.
    Benchmark("hpack/request/decode-cold") { benchmark in
        var seed = HPACKEncoder(maxDynamicTableSize: 4_096)
        let block = seed.encode(realisticRequestFields)
        for _ in benchmark.scaledIterations {
            block.withUnsafeBytes { raw in
                var decoder = HPACKDecoder(maxDynamicTableSize: 4_096)
                blackHole(try? decoder.decode(raw.bytes))
            }
        }
    }

    // The steady state on a reused connection: the dynamic table is warm, so the repeated request is
    // mostly indexed references (§6.1) — no literal decode, no per-field String. This is the path
    // that runs every request after the first, i.e. the real HTTP/2 throughput hot path.
    Benchmark("hpack/request/decode-warm") { benchmark in
        // All priming (encode + the first-request warm-up decode) happens once at module scope below,
        // so the measured loop is *only* the steady-state indexed decode — not the cold warm-up. A
        // per-call copy of the warmed decoder is a cheap COW retain; the indexed block never mutates
        // the table, so the decoder stays warm across iterations.
        var decoder = warmedRequestDecoder
        for _ in benchmark.scaledIterations {
            indexedRequestBlock.withUnsafeBytes { raw in
                blackHole(try? decoder.decode(raw.bytes))
            }
        }
    }

    // The server's response-encode side, cold: a fresh connection's first response — all literals +
    // incremental indexing (Huffman-encode + a table insert per field).
    Benchmark("hpack/response/encode-cold") { benchmark in
        for _ in benchmark.scaledIterations {
            var encoder = HPACKEncoder(maxDynamicTableSize: 4_096)
            blackHole(encoder.encode(realisticResponseFields))
        }
    }

    // Steady state: the encoder table is warm, so the repeated response is emitted as indexed
    // references (§6.1) — no Huffman encode, no insert. The mirror of request/decode-warm.
    Benchmark("hpack/response/encode-warm") { benchmark in
        var encoder = warmedResponseEncoder
        for _ in benchmark.scaledIterations {
            blackHole(encoder.encode(realisticResponseFields))
        }
    }
}

/// The RFC 7541 §5.2 string-literal encode benchmarks (Huffman-wins and raw-wins), split out so
/// ``registerHPACKBenchmarks()`` stays under the cyclomatic-complexity limit.
func registerHPACKStringBenchmarks() {
    Benchmark("hpack/String/encode") { benchmark in
        for _ in benchmark.scaledIterations {
            var output: [UInt8] = []
            HPACKString.encode(sampleFieldValue, into: &output)
            blackHole(output)
        }
    }

    // The "raw-wins" branch: a high-entropy value whose Huffman form is longer, so the literal bytes
    // are emitted. Today the length probe (Huffman.encodedByteLength) avoids the expensive encode pass
    // on this branch; this benchmark guards against a fusion that would force it.
    Benchmark("hpack/String/encode-raw") { benchmark in
        for _ in benchmark.scaledIterations {
            var output: [UInt8] = []
            HPACKString.encode(rawWinsFieldValue, into: &output)
            blackHole(output)
        }
    }
}

/// The realistic request re-encoded against a primed table, so it is a block of indexed references
/// (RFC 7541 §6.1) — the steady-state form a peer sends after the first request on a connection.
private let indexedRequestBlock: [UInt8] = {
    var encoder = HPACKEncoder(maxDynamicTableSize: 4_096)
    _ = encoder.encode(realisticRequestFields)  // first request: literals + incremental indexing
    return encoder.encode(realisticRequestFields)  // second request: all indexed references
}()

/// A decoder whose dynamic table is already warmed by the first request, ready to resolve the
/// indexed references in ``indexedRequestBlock`` (decoding those is read-only, so it stays warm).
private let warmedRequestDecoder: HPACKDecoder = {
    var decoder = HPACKDecoder(maxDynamicTableSize: 4_096)
    var encoder = HPACKEncoder(maxDynamicTableSize: 4_096)
    let primer = encoder.encode(realisticRequestFields)
    _ = primer.withUnsafeBytes { raw in try? decoder.decode(raw.bytes) }
    return decoder
}()

/// An encoder whose dynamic table is already primed by the first response, so re-encoding the same
/// response yields indexed references (RFC 7541 §6.1) — re-encoding does not mutate the table.
private let warmedResponseEncoder: HPACKEncoder = {
    var encoder = HPACKEncoder(maxDynamicTableSize: 4_096)
    _ = encoder.encode(realisticResponseFields)
    return encoder
}()
