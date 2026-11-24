# Audit & Transition Plan: `g-cqd/HTTP` → `AemiHTTP` (Aemi Ecosystem Consolidation)

**Date:** 2026-11-24  
**Repos audited:** `family/HTTP` (`g-cqd/HTTP`), `family/aemi` (`aemi-studio/aemi`), `Loom` (live 60 fps consumer)

---

## 1. Executive Summary

`family/HTTP` already depends on `aemi` (`AemiKernel` + `AemiKernels`), yet only **3 files** actually call into it (`FieldValidation.swift`, `HTTPDate.swift`, `IncrementalUTF8Validator.swift`). Meanwhile, `HTTP` maintains **~3,650+ lines** of duplicated runtime, kernel, concurrency, C-checksum, and test-kit infrastructure that already exists — often faster (NEON/AVX2), better tested, or already SE-0458 `StrictMemorySafety`-clean — inside `family/aemi`.

Conversely, `family/HTTP` contains **battle-tested, high-value primitives** (`CCRC32` ISO-HDLC gzip CRC-32 with ARM CRC32/PCLMULQDQ, `DeadlineWheel`, `ShardedMutex`, `BoundedLRU`, `AsyncExclusion`, `RollingWindow`, `RawSpan`-borrowing `ByteReader`, and `HTTPDeflate`) that belong in `aemi` as shared ecosystem building blocks.

Moving `HTTP` → **`AemiHTTP`** (relying completely on `AemiKernel`, `AemiKernels`, `AemiRuntime`, `AemiMetrics`, and `AemiTestKit`) simultaneously:
- Deletes ~3,100+ lines of duplicate code from `HTTP` (including **~150+ un-annotated SE-0458 unsafe sites** across `HTTPCore`, `HTTPTestSupport`, and `WebSocket`).
- Accelerates HTTP/1.1 parsing, chunked streaming, query decoding, Base64/WebSocket handshakes, and WebSocket masking via `CAemiKernels` NEON/SWAR kernels.
- Cuts per-frame heap copies and CPU/energy overhead on streaming workloads (such as Loom's 30–60 fps video feeds) by adopting `AemiKernel.ByteBufferPool` + `AemiRuntime.ScratchPool` + vectored/zero-copy sends.

---

## 2. Exact Duplication Inventory (`HTTP` → Replace with `aemi`)

| `HTTP` Source | LOC | Existing `aemi` Replacement | Performance / Safety Win |
|---|---:|---|---|
| `HTTPCore/Base64.swift` | 176 | `AemiKernel.Base64` + `AemiKernels` (`aemi_base64_encode/decode` NEON/SSSE3) | Vectorized encode/decode; eliminates scalar Swift table loops |
| `HTTPCore/QueryParameters.swift` (percent decode/encode) | 145 | `AemiKernel.PercentCoding` + `AemiKernels` (`aemi_percent_decode/encode` SIMD) | Zero-alloc SIMD scan for `%`/`+`; fast-path clean strings |
| `HTTPCore/ByteReader.swift` | 183 | `AemiKernel.ByteReader` + `Endian` (`loadLE16/32/64`, `loadBE16/32/64`) | Consolidates binary reading; promote `@_lifetime` `RawSpan` variant into `AemiKernel` |
| `HTTPConcurrency/TaskProvider.swift` + `LiveTaskProvider.swift` | ~50 | `AemiRuntime.TaskProvider` + `LiveTaskProvider` | Identical seam; unlocks `AemiTestKit.TaskProviderSpy` |
| `HTTPConcurrency/NowProvider.swift` | ~85 | `AemiRuntime.ClockSeam` (`LiveClock.monotonicNanoseconds`) | Single monotonic clock contract across the entire family |
| `HTTPTestSupport/*` (`Allocations`, `AsyncEventProbe`, `AsyncGate`, `ConstrainedStack`, `ContinuationRegistry`, `Fuzz`, `Oracles`, `SeededRNG`, `Tags`, `TestClock`, `ThreadGate`) + `CHTTPTestMalloc` | **~1,938** | `AemiTestKit` + `CAemiTestKitMalloc` | Removes **75 un-annotated unsafe sites + 1 suppression** in `HTTPTestSupport` immediately; leaves only HTTP-specific test doubles (`DribblingConnection`, `HangingConnection`, `SynthesizedUploadConnection`, `SharedDevTLSIdentity`) |

---

## 3. High-Performance Kernel Upgrades Inside `AemiHTTP` (Using Existing `CAemiKernels` NEON/SIMD)

`CAemiKernels` already ships **NEON (arm64) + AVX2/SSE4.2 (x86_64)** primitives that `HTTP` is not yet calling:

1. **HTTP/1.1 `HeaderParser.swift` & `RequestLineParser.swift`:**
   - Currently scans byte-by-byte in Swift loops for `\r\n`, `:`, and ASCII spaces.
   - Replace with `AemiKernels.findPair(0x0D, 0x0A)` (`aemi_find_pair` — NEON/SIMD CRLF finder) and `AemiKernels.findByte(0x3A)` (`aemi_find_byte` for `:`).
   - Use `AemiKernels.lowercaseASCII` / `AemiKernel.ASCII` for case-insensitive header matching without allocating lowercased `String`s.
2. **HTTP/1.1 `ChunkedBodyDecoder.swift` + `ResponseSerializer.swift` + `H1StreamWriter`:**
   - Use `AemiKernels.findPair(0x0D, 0x0A)` for chunk-size line scanning and `AemiKernel.Hex` (`aemi_hex_encode` / stack hex formatting) instead of `String(chunk.count, radix: 16)` per chunk (see [g-cqd/HTTP#2](https://github.com/g-cqd/HTTP/issues/2)).
   - Replace `var frame = Array("\(hex)\r\n".utf8); frame.append(contentsOf: chunk)` with either:
     - Pooled slab buffers from `AemiKernel.ByteBufferPool` / `AemiRuntime.ScratchPool`, or
     - Vectored `send(chunks: [ArraySlice<UInt8>])` / `writev` (POSIX) / `NWConnection.batch` + `DispatchData` (Network.framework) so **0 payload copies** occur per chunked frame.
3. **WebSocket `WebSocketFrameDecoder.swift` & `WebSocketFrameEncoder.swift`:**
   - Currently masks/unmasks payloads in a Swift loop.
   - Promote a 12-line NEON/AVX2 4-byte repeating XOR kernel (`aemi_xor_mask4(uint8_t *buf, size_t len, uint32_t mask)`) into `CAemiKernels` (64 bytes/iter on arm64 NEON, ~30+ GB/s).
4. **HPACK / QPACK (`HTTP2` / `HTTP3`) & Header Table:**
   - Reuse `AemiKernel.ByteCompare` (SIMD equality), `AemiKernel.WyHash` / `KeyedHash` (DoS-resistant header map hashing), and `AemiKernel.ByteBufferPool` for frame scratch buffers.

---

## 4. What `HTTP` Should **Promote Up** Into `family/aemi`

These `HTTP` components are genuinely general-purpose and higher-quality than anything currently in `aemi`:

| `HTTP` Component | Target `aemi` Module | Why Promote |
|---|---|---|
| `CCRC32/crc32.c` (ARM CRC32 + x86 PCLMULQDQ + slicing-by-8 ISO-HDLC gzip CRC-32) | **`CAemiKernels` + `AemiKernels`** (alongside existing `aemi_crc32c`) | `CAemiKernels` currently only has Castagnoli CRC-32C; adding ISO-HDLC CRC-32 (`aemi_crc32_ieee`) gives the entire family hardware gzip/zlib/PNG/ZIP checksumming and deletes `HTTP`'s separate `CCRC32` C target. |
| `HTTPServer/DeadlineWheel.swift` (O(1) hashed timer wheel) | **`AemiRuntime`** | Essential for low-energy, zero-timer-storm timeout management (replaces thousands of per-connection `Task.sleep` timers that wake CPU cores and burn battery). |
| `HTTPConcurrency/ShardedMutex.swift`, `BoundedLRU.swift`, `SharedBoundedLRU.swift`, `AsyncExclusion.swift`, `RollingWindow.swift` | **`AemiRuntime`** / **`AemiMetrics`** | High-contention concurrent primitives + bounded caches + sliding rate windows needed by servers, caches, and streaming apps alike (e.g. Loom's `StreamHub` metrics window). |
| `HTTPCore/ByteReader.swift` `@_lifetime` `RawSpan` borrowing API | **`AemiKernel`** | Compiler-checked lifetime-safe zero-copy parsing (`~Escapable` `RawSpan`) — strictly safer than pointer-based readers under SE-0458. |
| `HTTPDeflate` (pure-Swift + hardware CRC32 DEFLATE/gzip/zlib) | Optional **`AemiCompression`** (or keep as `AemiHTTPDeflate` until another family package needs it) | Zero system-library dependency; wait for a second consumer before moving out of `AemiHTTP`. |

---

## 5. Transport, Memory Safety & Energy/Battery Efficiency Assessment

### 5.1 Memory Safety (SE-0458 `StrictMemorySafety`)
Current `HTTP` budget (`strict-memory-safety-budget.tsv`): **426 un-annotated unsafe sites + 16 suppressions** (`HTTPTransport: 147`, `HTTPServer: 79`, `HTTPCore: 76`, `HTTPTestSupport: 75`, `HTTP1: 23`, `HTTP2: 21`, `WebSocket: 13`, `HTTP3: 8`).
- Consolidating `HTTPTestSupport` → `AemiTestKit` and `HTTPCore` primitives → `AemiKernel`/`AemiKernels` immediately eliminates **~140+ unsafe sites**.
- Moving low-level SIMD/C routines (CRC-32, XOR-mask4, CRLF scan) into `CAemiKernels` keeps Swift layers pure-safe (`Span` / `RawSpan` / `ByteBufferPool`) and lets `HTTP1`, `HTTP2`, `HTTP3`, `WebSocket`, and `HTTPCore` graduate into `strictMemorySafeTargets` cleanly.
- `HTTPTransport` (`POSIXKqueue`, `SwiftSystem`, `NetworkFramework`) should retain `StrictMemorySafety` with explicit `unsafe` markers localized to syscall wrappers (`kevent`, `writev`, `readv`, `setsockopt`).

### 5.2 Energy, Battery & CPU Efficiency
1. **Eliminate per-frame allocations & double copies** ([g-cqd/HTTP#2](https://github.com/g-cqd/HTTP/issues/2)):
   - Add `send(iovecs:)` / `writev` on POSIX backbones and `NWConnection.batch` + `DispatchData` on `NetworkFrameworkConnection`.
   - Use `AemiKernel.ByteBufferPool` for connection read buffers and response serialization instead of allocating a fresh `[UInt8]` per request/chunk.
2. **Fix `posixKqueue` custom `TaskExecutor` shutdown race** ([g-cqd/HTTP#3](https://github.com/g-cqd/HTTP/issues/3)):
   - Drain all child connection tasks pinned via `withTaskExecutorPreference(kqueueLoop)` before stopping the kqueue loop, preventing `_os_unfair_lock_unowned_abort` inside `swift_task_cancelImpl`.
   - Once fixed, `posixKqueue` (single event-loop thread, direct `kevent` sleep with 0 idle wakeups, `TCP_NODELAY`, `writev`) becomes the lowest-energy, lowest-latency backbone on macOS/Linux.
3. **Coalesced timer wheel & per-stream idle timeouts** ([g-cqd/HTTP#4](https://github.com/g-cqd/HTTP/issues/4)):
   - Keep `DeadlineWheel` coarse tick coalescing (1 timer wakeup per wheel tick rather than 1 timer per connection) for Apple Silicon E-core residency and battery life.
   - Separate `producerIdleTimeout` from socket `writeTimeout` on `ResponseStream` so event-driven push streams (SSE, screen capture) don't need artificial heartbeats or huge global timeouts.
4. **`TCP_NODELAY` & QoS configuration on `TransportConfiguration`:**
   - Expose `tcpNoDelay: Bool` (default `true` for interactive/streaming) and `qos` on `TransportConfiguration` so `NetworkFrameworkTransport` and `POSIXKqueue` don't stall small packets on Nagle/delayed-ACK (up to 40–200 ms latency penalty).

---

## 6. Phased Transition Roadmap (`g-cqd/HTTP` → `AemiHTTP`)

### Phase 0 — Package Identity & Compatibility Shim (Low Risk, 1 PR)
- Rename package/repo target namespace to **`AemiHTTP`** (`AemiHTTPCore`, `AemiHTTP1`, `AemiHTTP2`, `AemiHTTP3`, `AemiHTTPServer`, `AemiHTTPClient`, `AemiHTTPTransport`, `AemiWebSocket`) or keep an umbrella `AemiHTTP` product re-exporting sub-modules.
- Resolve the SwiftPM identity conflict (`github.com/aemi-studio/aemi` vs local `../aemi`) via a single canonical `aemi` dependency URL/tag.

### Phase 1 — Upstream Promotions to `family/aemi` (2–3 PRs)
1. Promote `CCRC32` → `CAemiKernels` (`aemi_crc32_ieee`) + add `aemi_xor_mask4` NEON/AVX2 kernel.
2. Promote `DeadlineWheel`, `ShardedMutex`, `BoundedLRU`, `SharedBoundedLRU`, `AsyncExclusion`, `RollingWindow` → `AemiRuntime` / `AemiMetrics`.
3. Promote `@_lifetime` `RawSpan` `ByteReader` overloads → `AemiKernel`.

### Phase 2 — Cut Over `AemiHTTP` Internals to `aemi` (3–4 PRs)
1. Delete `HTTPConcurrency` → import `AemiRuntime`.
2. Delete duplicated files in `HTTPTestSupport` + `CHTTPTestMalloc` → import `AemiTestKit`.
3. Replace `HTTPCore/Base64`, `QueryParameters` percent coding, `CRC32`, and `ByteReader` with `AemiKernel` / `AemiKernels`.
4. Wire `AemiKernels.findPair(0x0D, 0x0A)` / `findByte` into `HTTP1` (`HeaderParser`, `RequestLineParser`, `ChunkedBodyDecoder`) and `aemi_xor_mask4` into `WebSocket`.

### Phase 3 — Zero-Copy Streaming & Transport Hardening (2–3 PRs)
1. Implement vectored/zero-copy `H1StreamWriter` (`writev` / `NWConnection.batch` + `DispatchData`, stack hex length, `ByteBufferPool`) — closes `g-cqd/HTTP#2`.
2. Fix `KqueueEventLoop` task-executor drain on shutdown — closes `g-cqd/HTTP#3`.
3. Add `ResponseStream.producerIdleTimeout` + `TransportConfiguration.tcpNoDelay` — closes `g-cqd/HTTP#4`.
4. Ratchet `strict-memory-safety-budget.tsv` down to **0** across all protocol & core targets, graduating them into `strictMemorySafeTargets`.

### Phase 4 — Benchmarks & Energy Gates (`litmus` + `AemiTestKit.Allocations`)
- Add `AemiTestKit.Allocations` zero-allocation regression tests for:
  - HTTP/1.1 request/header parse hot path
  - Chunked streaming write (`H1StreamWriter.write`)
  - WebSocket frame decode/mask
- Run `Benchmarking/Bench` before/after Phase 2 and Phase 3 tracking throughput (req/s), p99 latency, heap allocations/req, and CPU time (`getrusage` / `AemiMetrics.ProcessProbe`).
