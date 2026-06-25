//
//  Benchmarks.swift
//  HTTPBenchmarks
//
//  Entry point for the Ordo benchmark runner. The `BenchmarkPlugin` generates `main` and invokes the
//  `benchmarks` closure; each registration function lives in its own file, grouped by module.
//

import Benchmark

let benchmarks: @Sendable () -> Void = {
    // Iron-Law metrics, made explicit (not the library default) so they cannot silently change and
    // so committed baselines can gate on them: `instructions` and `mallocCountTotal` are the
    // low-noise pair we regression-gate; wall/CPU/throughput/peak are captured for attribution.
    Benchmark.defaultConfiguration.metrics = [
        .instructions, .mallocCountTotal, .cpuTotal, .wallClock, .throughput, .peakMemoryResident
    ]
    // Per-metric tolerances for `swift package benchmark baseline compare`: only the deterministic,
    // machine-independent metrics are gated — mallocs are exact (no drift allowed), instructions get
    // a small tolerance for libc/runtime variance. wall-clock / CPU / throughput stay captured for
    // attribution but are too machine-dependent to gate portably (no threshold → never fail a compare).
    // (The exact per-op allocation ceilings on the hot paths are locked deterministically in the test
    // suite via `expectAllocations`, which runs in the existing `swift test` CI gate.)
    Benchmark.defaultConfiguration.thresholds = [
        .mallocCountTotal: .init(absolute: [.p90: 0, .p99: 0]),
        .instructions: .init(relative: [.p90: 5.0, .p99: 5.0])
    ]

    registerCoreBenchmarks()  // HTTPCore — byte primitives, validation, fields
    registerHTTP1Benchmarks()  // HTTP/1.1 — request/header/chunked parsers + serializer
    registerHPACKBenchmarks()  // HPACK — integer/string codecs + header-block round-trip
    registerHTTP2Benchmarks()  // HTTP/2 — frame layer + the sans-I/O connection engine (GET/POST)
    registerQPACKBenchmarks()  // QPACK — RFC 9204 integer/string codecs + field-section round-trip
    registerHTTP3Benchmarks()  // HTTP/3 — QUIC varint codec + RFC 9114 frame decode
    registerWebSocketBenchmarks()  // WebSocket — RFC 6455 frame decode (masked) + encode
    registerTransportBenchmarks()  // every backbone — loopback echo + in-memory abstraction
    registerCompressionBenchmarks()  // gzip CRC-32 backends — slice1 vs slice8 vs zlib vs ARM
    registerColdPathBenchmarks()  // reject/error branches — adversarial-input cost (cold paths)
}
