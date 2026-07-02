# HTTP

A from-scratch, **SwiftNIO-free** HTTP/1.1 · HTTP/2 · HTTP/3 server library for Apple
platforms **and Linux**, written in Swift 6.4. On Apple platforms it builds directly on
**Network.framework**; on Linux it runs on an **`epoll`** backbone with a portable
(vendored-BoringSSL) TLS path — HTTP/3 stays Apple-only (see [Platform support](#platform-support)).
It is designed to be a small, reusable **API package** that other projects embed.

> **Status:** Work in progress (TDD, milestone-by-milestone). `HTTPCore`, the HTTP/1.1 engine,
> HPACK, the four transport backbones, and an HTTP/1.1 server runtime are in place. The HTTP/2
> sans-I/O connection engine receives requests end-to-end (preface, SETTINGS, HEADERS/CONTINUATION
> with the flood guard, HPACK, DATA, and the §5.1 stream state machine); response encoding, inbound
> flow control, the Rapid Reset defense, and transport/ALPN wiring are in active development. The
> routing DSL is not built yet. See the milestone list below for implemented vs planned.

## Why

- **Closest to the hardware on Apple platforms, without NIO.** The transport is
  `NWListener` / `NWConnection` / `NWConnectionGroup` (TLS, ALPN and QUIC included), bridged to
  Swift Concurrency. No `EventLoop`, no NIO channel pipeline.
- **Standards-first.** Every parser and validator cites the exact RFC section it implements.
- **Failsafe.** Hostile input is bounded by design: iterative (non-recursive) parsers, strict
  limits with fail-closed behavior, and fuzz/property tests on every parser.

## Design principles

| Principle | How |
|---|---|
| **Sans-I/O engines** | Protocol engines are pure state machines (`feed(bytes) → events`); Network.framework is isolated to `HTTPTransport`. Enables millisecond unit tests, fuzzing, and reuse. |
| **No recursion** | All parsers/tries/Huffman decoders are explicit iterative loops — no stack exhaustion on adversarial input. |
| **Strict safety** | Swift 6 complete concurrency, value types, typed `throws`; no force-unwrap / force-cast / IUO (lint-enforced). |
| **Zero-copy first** | Parsing runs over borrowed buffers via a bounds-checked `ByteReader` that returns offsets/ranges — never intermediate copies. Bytes become owned values only when they must outlive the receive buffer. |
| **Multithreaded** | Work scales across cores: each connection is served by its own `Task` off a discarding task group, and the hot path holds no global locks — per-connection state is isolated and guarded by `Mutex`/`Atomic` from `Synchronization`. |
| **Minimal allocation** | Reused scratch space and ring-buffer compression tables on top of the zero-copy reader — targeting 200k rps. |
| **Own currency types** | First-party `HTTPRequest`/`HTTPResponse`/`HTTPFields`/`HTTPStatus`/`HTTPMethod` (RFC 9110), shared across h1/h2/h3 — **zero external dependencies**. |

## Standards

**Implemented:** HTTP Semantics (RFC 9110), HTTP/1.1 (RFC 9112) with request-smuggling defenses,
and HPACK (RFC 7541). The HTTP/2 (RFC 9113) frame layer, SETTINGS, flow-control window, and request
mapping exist as sans-I/O primitives; the connection/stream engine that drives them is in progress.

**Planned:** HTTP/2 connection engine, Caching (9111), HTTP/3 (9114) + QPACK (9204) over QUIC
(Network.framework, RFC 9000/9001/9002), Structured Fields (8941), Cookies (6265bis), Priorities
(9218), Alt-Svc (7838), WebSocket (6455 / 9220).

Security hardening is traced to its RFC §/CVE in `Docs/Documentation/Security.md` (e.g. HTTP/2 Rapid
Reset CVE-2023-44487, CONTINUATION flood CVE-2024-27316, request smuggling, decompression bombs).

## Platform support

| Platform | HTTP/1.1 | HTTP/2 | WebSocket | HTTP/3 | TLS | Compression (out) |
|---|:--:|:--:|:--:|:--:|---|---|
| macOS 15+ / iOS 18+ | ✅ | ✅ | ✅ | ✅ | Network.framework | br · gzip · zstd† |
| Linux (glibc · x86-64 / arm64) | ✅ | ✅ | ✅ | — | portable BoringSSL† | gzip · zstd† · br† |

The sans-I/O engines (h1/h2/h3, HPACK/QPACK, WebSocket) are pure Swift and identical on every platform;
only the I/O floor differs — Network.framework / kqueue on Apple, an `epoll` backbone on Linux. The full
test suite runs on both (CI: `ubuntu-latest` + macOS; locally, `scripts/linux-test.sh` via apple/container).
**HTTP/3 is Apple-only** in v1 — QUIC is provided by Network.framework; a portable QUIC story is a separate
follow-up.

† Opt-in build flags: `HTTP_ZSTD` (zstd) and `HTTP_BROTLI` (Brotli, via system libbrotli) codings, and
`HTTP_PORTABLE_TLS` (the vendored, symbol-prefixed BoringSSL TLS backbone — the default Apple build uses
Network.framework's TLS). On Linux gzip is always available (system zlib). See
[ADR 0004](Docs/Documentation/adr/0004-portable-tls-backbone.md).

## Requirements

- Swift 6.4+. macOS 15.6+ / iOS 18+; Linux (glibc — Ubuntu 22.04+, x86-64 / arm64) for HTTP/1.1 · HTTP/2 · WebSocket.
- Strictest reuse-safe settings (Swift 6 language mode; `ExistentialAny`,
  `InternalImportsByDefault`, `MemberImportVisibility`). Warnings-as-errors and sanitizers run in CI.

## Build & test

Build artifacts are kept out of the source tree, in `/tmp`:

```sh
swift build  --scratch-path /tmp/swiftpm-build/HTTP
swift test   --scratch-path /tmp/swiftpm-build/HTTP
swift format lint --strict --recursive Sources Tests Package.swift
swiftlint lint --strict
```

## Milestones

- **M0** — Package scaffold & tooling ✅
- **M1** — `HTTPCore` (RFC 9110 semantics, byte primitives, limits, Huffman) ✅
- **M2** — HTTP/1.1 engine (RFC 9112) + smuggling defenses ✅
- **M3** — `HTTPTransport` (four backbones: Network.framework + POSIX kqueue/Dispatch/swift-system) ✅; TLS+ALPN, dev certs 🚧
- **M4** — HTTP/1.1 server ✅; routing result-builder DSL 🚧
- **M5** — HPACK (7541) ✅ + HTTP/2 (9113): frame primitives ✅, sans-I/O connection/stream engine (request path) ✅; response encoding · flow control · Rapid Reset · ALPN wiring 🚧
- **M6** — Middleware (compression, caching, cookies, CORS) + WebSocket — planned
- **M7** — QPACK (9204) + HTTP/3 (9114) over QUIC — planned
- **M8** — Hardening, benchmarks, example server (example ✅; benchmarks 🚧)

## License

MIT — see [LICENSE](LICENSE).
