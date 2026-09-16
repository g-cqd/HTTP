//
//  CompressionBenchmarks.swift
//  HTTPBenchmarks
//
//  RFC 1952 §8 — the gzip CRC-32 computed over the *uncompressed* body on every compressed response.
//  Compares the portable slice-by-1 and slice-by-8 backends with ARMv8 CRC32 and x86 PCLMULQDQ.
//  Hardware backends fall back to the table when unavailable. DEFLATE is not measured here.
//

import Benchmark
import HTTPCore

func registerCompressionBenchmarks() {
    let sizes: [(label: String, body: [UInt8])] = [
        ("1KiB", crcBody1KiB), ("16KiB", crcBody16KiB), ("256KiB", crcBody256KiB)
    ]
    let backends: [(label: String, backend: CRC32.Backend)] = [
        ("slice1", .sliceBy1), ("slice8", .sliceBy8), ("x86", .x86), ("arm", .arm)
    ]
    for size in sizes {
        for backend in backends {
            Benchmark("crc32/\(size.label)/\(backend.label)") { benchmark in
                for _ in benchmark.scaledIterations {
                    blackHole(CRC32.checksum(size.body, backend: backend.backend))
                }
            }
        }
    }
}
