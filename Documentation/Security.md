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
are implemented, now with a time-windowed rolling budget (see the audit-hardening note below).

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
On the HTTP/2 engine: a unified **time-windowed abuse budget** that decays over `streamResetInterval`
and charges *server-emitted* RST_STREAM, closing the **MadeYouReset** bypass (H2-F1/F2, CVE-2025-8671 /
CVE-2023-44487); trailers scoped and validated as **stream** errors (H2-F2/F3/F5, §8.1); and a frame on
a closed stream reported as **STREAM_CLOSED** via a bounded recently-closed-id set (F1, §5.1).

### Deep hardening (2026-06-25)
Traced in `Documentation/audit/2026-06-25-deep-hardening-audit.md`:
- **Secure-by-default limits.** `maxConnections` / `maxConnectionsPerClient` default to 65 536 / 1 024
  (were 1 048 576, which defanged the global/per-client caps); `maxConcurrentStreams` stays a bounded
  128. `HTTPLimits.highThroughput` restores the permissive ceilings for trusted/benchmark use;
  `HTTPLimits.hardened` tightens them further (CWE-770).
- **Chunked body-phase buffer bounded.** An endless chunk-size / chunk-ext / trailer line with no CRLF
  is failed closed by a per-line bound (`ChunkedBodyDecoder.readLine`) rather than buffered without
  limit (RFC 9112 §7.1; CWE-400/770).
- **HTTP/2 abuse budget completed.** A server-emitted REFUSED_STREAM is now charged (closing the
  concurrency-cap Rapid-Reset/MadeYouReset bypass, CVE-2025-8671 / CVE-2023-44487); zero-length DATA
  (CVE-2019-9518), PRIORITY (CVE-2019-9513), WINDOW_UPDATE-on-closed, and SETTINGS-ACK charge a separate
  `maxControlFramesPerInterval` budget (`HTTP2Connection+AbuseBudget.swift`).
- **WebSocket Origin is secure-by-default.** The default policy admits only a no-`Origin` (non-browser)
  client and rejects browser origins until allowlisted — closing the CSWSH default-open (RFC 6455 §10.2,
  CWE-346/1385; `WebSocketHandler`).
- **WebSocket text UTF-8 validated incrementally** across fragments — rejected at the first bad octet,
  not after the whole message buffers (RFC 6455 §8.1; `IncrementalUTF8Validator`).
- **Cookie attributes validated.** `SetCookie` validates `Domain`/`Path` octets + the `__Host-` /
  `__Secure-` prefix invariants; `headerValue` is fail-closed (`String?`), so an attacker-controlled
  attribute cannot inject a directive or split the header (RFC 6265bis §4.1; CWE-113).
- **CORS hardened.** `.any` never pairs a wildcard with credentials; `.allowList` does safe credentialed
  multi-origin; a reflected origin carries `Vary: Origin` (Fetch §3.2; CWE-942; `CORSMiddleware.swift`).
- **`Expect: 100-continue`** handled: an interim `100 Continue` (or `417` for an unsupported
  expectation) is sent before the body, so a compliant client no longer stalls (RFC 9110 §10.1.1).

Single-source-of-truth refactor: the HTTP/2 and HTTP/3 request mappers were unified into one
`HTTPCore.RequestMapper`, so the §8.3 / §4.3 pseudo-header + field validation lives in exactly one place.

## Pending (tracked)

These are **not yet enforced** — do not rely on them until the referenced milestone lands.

| Gap | Attack | Plan |
|---|---|---|
| **transport**: strict ALPN no-overlap rejection (the platform does not send `no_application_protocol`) | ALPACA-class cross-protocol confusion | reject a TLS connection that resolved to a nil / unadvertised protocol (T-F6) |
| **transport(kqueue)**: a parked read/write continuation leaks when the fd is closed mid-wait | task/memory leak via the Slowloris-timeout path | drain pending resumers in `KqueueEventLoop.closeDescriptor` (T-F7) |
| **transport(posix)**: accept-error back-off (`EMFILE`/`ENFILE`) `usleep`s on the shared accept/event-loop queue | FD-pressure latency for all connections | move the back-off off the shared queue (T-F8; transport follow-up) |
| **transport(posix)**: IPv4-only listener; hard-coded `listen` backlog | coherency vs the dual-stack Network.framework backbone | dual-stack `AF_INET6` + configurable backlog (T-F12/T-F14; transport follow-up) |

> Resolved since the first review (now implemented): per-client **and** global connection caps; the
> CONTINUATION flood guard (CVE-2024-27316); the h1 header-accumulation cap; the HTTP/2 Rapid-Reset
> *counter*, `maxConcurrentStreams`, and inbound flow control; TLS/ALPN with a TLS 1.3 floor **and**
> pinned ceiling; decompression bounds (gzip middleware); and the 2026-06-22 audit-driven items above.
