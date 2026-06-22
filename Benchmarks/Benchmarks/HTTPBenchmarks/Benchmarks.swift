//
//  Benchmarks.swift
//  HTTPBenchmarks
//
//  Entry point for the Ordo benchmark runner. The `BenchmarkPlugin` generates `main` and invokes the
//  `benchmarks` closure; each registration function lives in its own file, grouped by module.
//

import Benchmark

let benchmarks: @Sendable () -> Void = {
    registerCoreBenchmarks()  // HTTPCore — byte primitives, validation, fields
    registerHTTP1Benchmarks()  // HTTP/1.1 — request/header/chunked parsers + serializer
    registerHPACKBenchmarks()  // HPACK — integer/string codecs + header-block round-trip
    registerHTTP2Benchmarks()  // HTTP/2 — frame layer + the sans-I/O connection engine (GET/POST)
    registerWebSocketBenchmarks()  // WebSocket — RFC 6455 frame decode (masked) + encode
    registerTransportBenchmarks()  // every backbone — loopback echo + in-memory abstraction
    registerCompressionBenchmarks()  // gzip CRC-32 backends — slice1 vs slice8 vs zlib vs ARM
}
