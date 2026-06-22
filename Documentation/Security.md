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

## Pending (tracked)

These are **not yet enforced** — do not rely on them until the referenced milestone lands.

| Gap | Attack | Plan |
|---|---|---|
| **h1**: header-accumulation buffer is unbounded before the `CRLF CRLF` terminator (`HTTPServer.readRequest`) | memory exhaustion | cap at `maxRequestLineLength + maxHeaderListSize` → 431 *before* the terminator |
| **h2**: HTTP/2 Rapid Reset | CVE-2023-44487 | RST churn counter enforcing `maxStreamResetsPerInterval` over `streamResetInterval` → GOAWAY |
| **h2**: `maxConcurrentStreams` not enforced on inbound HEADERS (`HTTP2Connection`) | stream exhaustion | reject the (N+1)th open stream → REFUSED_STREAM |
| **h2**: inbound flow control not enforced (`WINDOW_UPDATE` is a no-op) | unbounded buffering / sender stall | track the receive window and emit `WINDOW_UPDATE` |
| Decompression ratio/size not enforced | content-coding bomb | when content-coding lands |
| TLS/ALPN hardening | downgrade / weak ciphers | when TLS config lands (Network.framework) |

> Resolved since the first review: per-client connection cap (`maxConnectionsPerClient`) and the
> HTTP/2 CONTINUATION flood guard (CVE-2024-27316) are now implemented.
