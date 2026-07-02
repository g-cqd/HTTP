# HTTP

A from-scratch, **SwiftNIO-free** HTTP/1.1 · HTTP/2 · HTTP/3 server library for Apple
platforms **and Linux**, written in Swift 6.4. On Apple platforms it builds directly on
**Network.framework**; on Linux it runs on an **`epoll`** backbone with a portable
(vendored-BoringSSL) TLS path — HTTP/3 stays Apple-only (see [Platform support](#platform-support)).
It is designed to be a small, reusable **API package** that other projects embed.

> **Status:** All milestones (M0–M8) shipped. HTTP/1.1, HTTP/2 (HPACK, flow control, Rapid Reset
> and CONTINUATION-flood defenses, RFC 9218 priorities), and HTTP/3 (QPACK, WebSocket-over-h3 /
> RFC 9220) serve end-to-end behind one server runtime: routing result-builder DSL, ~25 middleware
> (compression in/out, caching, sessions, CORS, rate limiting, problem+json, timeouts …),
> route-scoped WebSocket with a broadcast hub, streaming request/response bodies, per-route body
> limits, mutual TLS with the full peer identity as request context, static files with
> `sendfile(2)` zero-copy on the POSIX backbones, hot certificate/responder reload, and an
> observability module. Remaining tails are tracked in
> `Docs/Documentation/roadmap/` (conformance-CI promotion, gated perf items, staged h2
> back-pressure refinement).

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

**Implemented:** HTTP Semantics (RFC 9110), Caching (RFC 9111), HTTP/1.1 (RFC 9112) with
request-smuggling defenses, HPACK (RFC 7541) + HTTP/2 (RFC 9113) with the Rapid Reset and
CONTINUATION-flood defenses, QPACK (RFC 9204) + HTTP/3 (RFC 9114) over QUIC (Network.framework,
RFC 9000/9001/9002), WebSocket (RFC 6455) over h1 and h2/h3 (RFC 8441 / RFC 9220) with
permessage-deflate (RFC 7692), Structured Fields (RFC 8941), Cookies (RFC 6265), Priorities
(RFC 9218), Alt-Svc (RFC 7838), TLS 1.3 (RFC 8446) with ALPN (RFC 7301), mutual TLS with X.509
peer identity (RFC 5280) and PEM intake (RFC 7468), problem+json (RFC 9457), multipart forms
(RFC 7578), JWT verification (RFC 7519), and HKDF (RFC 5869).

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

All shipped (see `Docs/Documentation/roadmap/` for the post-milestone production roadmaps):

- **M0** — Package scaffold & tooling ✅
- **M1** — `HTTPCore` (RFC 9110 semantics, byte primitives, limits, Huffman) ✅
- **M2** — HTTP/1.1 engine (RFC 9112) + smuggling defenses ✅
- **M3** — `HTTPTransport` (Network.framework + POSIX kqueue/Dispatch/swift-system + Linux epoll + portable BoringSSL TLS), TLS + ALPN, mTLS, SNI multi-cert, hot reload, dev certs ✅
- **M4** — HTTP/1.1 server, routing result-builder DSL, request seam (context/body), streaming bodies ✅
- **M5** — HPACK (7541) + HTTP/2 (9113): full sans-I/O connection/stream engine, response encoding, flow control, Rapid Reset + CONTINUATION-flood defenses, RFC 9218 priorities, ALPN wiring ✅
- **M6** — Middleware (~25: compression in/out, caching, cookies, CORS, sessions, rate limiting, timeouts, problem+json, …) + WebSocket (route-scoped, hub, permessage-deflate) ✅
- **M7** — QPACK (9204) + HTTP/3 (9114) over QUIC, WebSocket-over-h3 (9220) ✅
- **M8** — Hardening (fuzz + conformance suites, sanitizers, trap-free request path), benchmarks, example server ✅

## License

MIT — see [LICENSE](LICENSE).
