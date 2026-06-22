//
//  CompressionBenchmarks.swift
//  HTTPBenchmarks
//
//  RFC 1952 §8 — the gzip CRC-32 computed over the *uncompressed* body on every compressed response.
//  Compares the backends (naive slice-by-1 baseline, slicing-by-8, zlib, ARMv8 CRC32) across body
//  sizes. The DEFLATE itself is Apple's `Compression` framework and is not measured here. (On x86,
//  the `arm` case falls back to the table and the `zlib` case is the PCLMULQDQ path.)
//

import Benchmark
import HTTPCore

func registerCompressionBenchmarks() {
    let sizes: [(label: String, body: [UInt8])] = [
        ("1KiB", crcBody1KiB), ("16KiB", crcBody16KiB), ("256KiB", crcBody256KiB),
    ]
    let backends: [(label: String, backend: CRC32.Backend)] = [
        ("slice1", .sliceBy1), ("slice8", .sliceBy8), ("zlib", .zlib), ("arm", .arm),
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
