# Security posture

This document traces each hardening measure to the RFC section or CVE it addresses, and is explicit
about what is **implemented** today versus **pending**. The threat model assumes all bytes from the
network are hostile until validated (input crosses the trust boundary at `TransportConnection`).

The sans-I/O engines fail **closed**: a malformed or hostile message produces a typed error mapped
to the correct protocol response (4xx / RST_STREAM / GOAWAY), never a silent truncation, fail-open,
or trap.

## Implemented

### Memory & control-flow safety
| Defense | Mechanism | Reference |
|---|---|---|
| No out-of-bounds reads on adversarial input | `ByteReader` is `~Escapable` over a `RawSpan`; every accessor is bounds-checked | `Sources/HTTPCore/ByteReader.swift` |
| No stack exhaustion | All parsers/decoders are iterative — no recursion | `Huffman.swift`, `HPACK*`, `HTTP1/*` |
| No force-unwrap / force-cast / `try!` / `as Any` | Lint-enforced (SwiftLint `force_*`, `implicitly_unwrapped_optional`) | `.swiftlint.yml` |
| Data-race safety | Swift 6 language mode, `Sendable` value types, `Mutex`/`Atomic`; ASan+TSan in CI | `Package.swift`, `.github/workflows/ci.yml` |

### Request smuggling (RFC 9112)
| Defense | Reference | Location |
|---|---|---|
| `Content-Length` + `Transfer-Encoding` together rejected | RFC 9112 §6.1 | `HTTP1/RequestParser.swift:96` |
| Only final `chunked` accepted; compound codings rejected | RFC 9112 §6.1/§7.1 | `RequestParser.swift` (`isChunked`) |
| Conflicting / malformed `Content-Length` (incl. comma lists) → invalid | RFC 9112 §6.3 | `HTTPCore/HTTPFields+ContentLength.swift` |
| Obsolete line folding (obs-fold) rejected | RFC 9112 §5.2 | `HTTP1/HeaderParser.swift:39` |
| Request-target control/DEL/whitespace rejected before materialization | RFC 9110 §4 | `HTTP1/RequestLineParser.swift:52` |
| Strict `CRLF`; bare CR is a framing error | RFC 9112 §2.2 | `RequestLineParser.swift`, `HeaderParser.swift` |
| Exactly one `Host` for HTTP/1.1 | RFC 9110 §7.2 | `RequestParser.swift:75` |

### Header injection / response splitting
| Defense | Reference | Location |
|---|---|---|
| Field values reject CR, LF, NUL (and other C0 controls, DEL) | RFC 9110 §5.5, CWE-113 | `HTTPCore/FieldValidation.swift:89` |
| Field names must be a `token` | RFC 9110 §5.6.2 | `FieldValidation.swift:41` |

### Integer overflow
| Defense | Reference | Location |
|---|---|---|
| Chunk-size hex accumulation overflow-checked | RFC 9112 §7.1 | `ChunkedDecoder.swift:70` |
| Body size bounded without trapping addition | RFC 9110 §15.5 | `ChunkedDecoder.swift:42` |
| HPACK prefix-integer magnitude + continuation-octet (padding) bound | RFC 7541 §5.1 | `HPACK/HPACKInteger.swift:64` |
| Flow-control window increment ≤ 2³¹−1 | RFC 9113 §6.9.1 | `HTTP2/HTTP2FlowControlWindow.swift:59` |

### Resource exhaustion (defense-in-depth limits — `HTTPLimits`)
| Limit | Attack | Response |
|---|---|---|
| `maxRequestLineLength` | buffer abuse | 414 |
| `maxFieldSize`, `maxHeaderListSize`, `maxFieldCount` | header abuse / cookie-splitting | 431 |
| `maxBodySize` | oversized body | 413 |
| HPACK cumulative decoded-list size; string-length; dynamic-table cap (§4.2/§6.3) | HPACK decompression bomb | COMPRESSION_ERROR |
| `headerReadTimeout` (cumulative), `idleTimeout`, `keepAliveTimeout` | Slowloris / slow-read | 408 / close |

### HTTP/2 (RFC 9113) — sans-I/O engine (request path)
Frame-size cap → FRAME_SIZE_ERROR (`HTTP2FrameDecoder.swift`); SETTINGS per-parameter validation
(`HTTP2Settings.swift`); HEADERS padding validation (`HTTP2HeadersFrame.swift`); pseudo-header
ordering/dedup, lowercase field-name enforcement (§8.2.1), forbidden connection-specific fields
(§8.2.2), `TE: trailers` only (`HTTP2RequestMapper.swift`); §5.1 stream state machine
(`HTTP2Stream.swift`); and the **CONTINUATION flood guard (CVE-2024-27316)** — caps on
CONTINUATION-frame count and cumulative block size → ENHANCE_YOUR_CALM
(`HTTP2HeaderBlockAccumulator.swift`). Request body bounded by `maxBodySize` (`HTTP2Connection.swift`).
Rapid-Reset *counter*, `maxConcurrentStreams` enforcement (→ REFUSED_STREAM), and inbound flow control
are implemented (see the Pending note on the Rapid-Reset rolling window).

### Audit-driven hardening (2026-06-22)
Traced in `Documentation/audit/2026-06-22-standards-and-improvements-audit.md`:
`SO_NOSIGPIPE` on every POSIX socket so a peer RST mid-`write` cannot kill the process (T-F1,
POSIX.1-2017); a WebSocket `Origin` allowlist hook against cross-site WebSocket hijacking (WS-F1,
RFC 6455 §10.2 / CWE-1385); an HPACK field-**count** cap closing the header-count bomb (HP-F1,
RFC 9113 §8.2.3); a **resumable chunked decoder** removing the O(n²) re-decode DoS, plus a
chunk-extension bound and trailer-field validation (H1-F1/F2/F3, RFC 9112 §7.1.1/§7.1.2); a global
connection ceiling `maxConnections` (T-F2); kqueue `EINTR`/`EAGAIN` parity (T-F3); a pinned TLS
**max** version with a configurable, 1.3-default range (T-F5, BCP 195); reject `Transfer-Encoding`
on HTTP/1.0 + unknown TE → 501 (H1-F5); and outbound WebSocket Close-code validation (WS-F6, §7.4.1).

## Pending (tracked)

These are **not yet enforced** — do not rely on them until the referenced milestone lands.

| Gap | Attack | Plan |
|---|---|---|
| **h2**: the Rapid-Reset / control-frame budgets are monotonic counters that never decay (`streamResetInterval` / `NowProvider` unused) | CVE-2023-44487 (long-window bypass + false positives on long-lived conns) | make them rolling-window rate limiters via the existing `NowProvider` / `TestClock` seam |
| **h2**: server-*emitted* RST_STREAM is not rate-counted | CVE-2025-8671 "MadeYouReset" (bypasses the reset counter) | charge the same reset budget when the engine emits RST_STREAM |
| **h2**: closed-stream → PROTOCOL_ERROR not STREAM_CLOSED; trailers skip field/pseudo-header validation; a 2nd HEADERS without END_STREAM is a *connection* (not *stream*) error | RFC 9113 §5.1 / §8.1 conformance (staged as `withKnownIssue` F1/F2/F3) | remember recently-closed stream IDs; validate trailer fields; scope the trailer error per-stream |
| **transport**: strict ALPN no-overlap rejection (the platform does not send `no_application_protocol`) | ALPACA-class cross-protocol confusion | reject a TLS connection that resolved to a nil / unadvertised protocol (T-F6) |
| **transport(kqueue)**: a parked read/write continuation leaks when the fd is closed mid-wait | task/memory leak via the Slowloris-timeout path | drain pending resumers in `KqueueEventLoop.closeDescriptor` (T-F7) |
| **ws**: the `inbound` drain uses `removeFirst` (O(n) per read) | quadratic CPU under dribbled frames | consumed-offset + compaction (WS-F4; performance lane) |
| **h1**: no `Expect: 100-continue` handling | stalled compliant clients / pause-desync | emit interim `100 Continue` or `417` (H1-F4) |

> Resolved since the first review (now implemented): per-client **and** global connection caps; the
> CONTINUATION flood guard (CVE-2024-27316); the h1 header-accumulation cap; the HTTP/2 Rapid-Reset
> *counter*, `maxConcurrentStreams`, and inbound flow control; TLS/ALPN with a TLS 1.3 floor **and**
> pinned ceiling; decompression bounds (gzip middleware); and the 2026-06-22 audit-driven items above.
