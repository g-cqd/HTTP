# Standards Corpus — vendored RFCs & conformance traceability

Authoritative offline copies of every RFC this server implements or directly extends, plus a
**traceability matrix** mapping each one to the code that implements it and the tests that prove it.

- **Why in-repo:** direct, greppable access while reading code or writing conformance tests
  (`grep -n "MUST" Standards/rfc9113.txt`), and a single place to answer *"are we compliant, and where?"*
- **Source:** `https://www.rfc-editor.org/rfc/rfcNNNN.txt` (authoritative ASCII), fetched 2026-06-24.
  Re-fetch with `Standards/fetch.sh`.
- **Citing in tests:** reference `Standards/rfcNNNN.txt` §X.Y in a suite name or comment so a reviewer can
  jump straight to the normative text the test encodes.

**Status legend:** ✅ implemented & tested · ◐ partial / platform-provided · ✗ vendored for reference, not implemented.

---

## HTTP/1.1

| RFC | Title | Governs | Source | Tests | Status |
|----|-------|---------|--------|-------|--------|
| [9112](rfc9112.txt) | HTTP/1.1 Message Syntax & Routing | request line, headers, framing, chunked, smuggling defense | `Sources/HTTP1/{RequestParser,RequestLineParser,HeaderParser,ChunkedDecoder,ChunkedBodyDecoder,BodyFraming,ResponseSerializer}.swift` | `Tests/HTTP1Tests/*` | ✅ |
| [9110](rfc9110.txt) | HTTP Semantics | methods, status, fields, request-target, HTTP-date | `Sources/HTTPCore/{HTTPMethod,HTTPStatus,HTTPStatus+Registered,FieldValidation,HTTPDate,HTTPFieldName}.swift` | `Tests/HTTPCoreTests/*` | ✅ |
| [9111](rfc9111.txt) | HTTP Caching | conditional requests, ETag / If-None-Match → 304 | `Sources/HTTPServer/Middleware/ConditionalRequestMiddleware.swift` | `Tests/HTTPServerTests/*` | ◐ conditional requests only |

## HTTP/2

| RFC | Title | Governs | Source | Tests | Status |
|----|-------|---------|--------|-------|--------|
| [9113](rfc9113.txt) | HTTP/2 | frames, streams, flow control, settings, request mapping, abuse budget | `Sources/HTTP2/*` (`HTTP2Connection*`, `HTTP2FrameDecoder`, `HTTP2RequestMapper`, `HTTP2FlowControlWindow`, `HTTP2Stream*`, `HTTP2HeaderBlockAccumulator`) | `Tests/HTTP2Tests/*` (incl. `Conformance/`) | ✅ |
| [7541](rfc7541.txt) | HPACK | header compression, dynamic table, Huffman | `Sources/HPACK/*`, `Sources/HTTPCore/Huffman*.swift` | `Tests/HPACKTests/*` | ✅ |

## HTTP/3

| RFC | Title | Governs | Source | Tests | Status |
|----|-------|---------|--------|-------|--------|
| [9114](rfc9114.txt) | HTTP/3 | frames, unidirectional/request streams, settings (sans-I/O) | `Sources/HTTP3/*` (`HTTP3Connection*`, `HTTP3FrameDecoder`, `HTTP3RequestMapper`, `HTTP3StreamRole`) | `Tests/HTTP3Tests/*` (incl. `Conformance/`) | ◐ sans-I/O engine; no UDP/QUIC transport |
| [9204](rfc9204.txt) | QPACK | header compression (static table + literals; dynamic table off in v1) | `Sources/QPACK/*`, `Sources/HTTPCore/Huffman*.swift` | `Tests/QPACKTests/*` | ◐ static-only (v1) |

## QUIC (HTTP/3 transport substrate)

| RFC | Title | Governs | Source | Tests | Status |
|----|-------|---------|--------|-------|--------|
| [9000](rfc9000.txt) | QUIC Transport | variable-length integers (§16), stream-ID classification | `Sources/HTTPCore/{QUICVarint,QUICStreamID}.swift` | `Tests/HTTPCoreTests/*` | ◐ varint/stream-ID only; transport is platform (`Sources/HTTPTransport/Quic/*` over Network.framework) |
| [9001](rfc9001.txt) | Using TLS to Secure QUIC | QUIC handshake / keys | platform (Network.framework) | — | ✗ external |
| [9002](rfc9002.txt) | QUIC Loss Detection & Congestion Control | recovery | platform (Network.framework) | — | ✗ external |

## WebSocket

| RFC | Title | Governs | Source | Tests | Status |
|----|-------|---------|--------|-------|--------|
| [6455](rfc6455.txt) | The WebSocket Protocol | framing, masking, handshake, close, ping/pong, fragmentation, UTF-8 | `Sources/WebSocket/*` | `Tests/WebSocketTests/*` | ✅ |
| [8441](rfc8441.txt) | Bootstrapping WebSockets with HTTP/2 | extended CONNECT (`:protocol`) | `Sources/HTTP2/HTTP2Connection+Connect.swift`, `Sources/HTTPServer/HTTPServer+WebSocket.swift` | `Tests/HTTP2Tests/*`, `Tests/HTTPServerTests/*` | ✅ |
| [9220](rfc9220.txt) | Bootstrapping WebSockets with HTTP/3 | extended CONNECT over h3 | — | — | ✗ not implemented |
| [7692](rfc7692.txt) | Compression Extensions (permessage-deflate) | per-message DEFLATE | — | — | ✗ not implemented (RSV1 rejected) |

## Content coding (compression)

| RFC | Title | Governs | Source | Tests | Status |
|----|-------|---------|--------|-------|--------|
| [1952](rfc1952.txt) | GZIP file format | gzip container + CRC-32 | `Sources/HTTPServer/Middleware/{CompressionMiddleware,Gzip}.swift`, `Sources/CCRC32/*`, `Sources/HTTPCore/CRC32.swift` | `Tests/HTTPServerTests/*` | ✅ |
| [1951](rfc1951.txt) | DEFLATE | the deflate algorithm | `Sources/HTTPServer/Middleware/Gzip.swift` (zlib) | — | ◐ via system zlib |
| [1950](rfc1950.txt) | ZLIB | zlib stream format | `Sources/HTTPServer/Middleware/Gzip.swift` (zlib) | — | ◐ via system zlib |

## Cookies / TLS / extensions / encoding

| RFC | Title | Governs | Source | Tests | Status |
|----|-------|---------|--------|-------|--------|
| [6265](rfc6265.txt) | HTTP State Management | cookie parsing | `Sources/HTTPCore/{Cookie,Cookies}.swift` | `Tests/HTTPCoreTests/*` | ◐ parsing |
| [8446](rfc8446.txt) | TLS 1.3 | TLS floor | `Sources/HTTPTransport/Network/NetworkFrameworkTLS.swift`, `Sources/HTTPTransport/Abstraction/{TransportTLS,TLSVersion}.swift` (platform) | `Tests/HTTPTransportTests/*` | ◐ platform |
| [7301](rfc7301.txt) | ALPN | protocol negotiation (`h2`, `http/1.1`) | `Sources/HTTPTransport/Network/NetworkFrameworkTLS.swift` | `Tests/HTTPTransportTests/*` | ✅ (Network.framework) |
| [7838](rfc7838.txt) | Alt-Svc | advertising HTTP/3 | `Sources/HTTPServer/HTTPServer+HTTP3.swift`, `Sources/HTTPCore/HTTPFieldName+Registered.swift` | — | ◐ advertisement |
| [9218](rfc9218.txt) | Extensible Prioritization | h2/h3 priorities | `Sources/HTTP2/*` (PRIORITY parsed) | `Tests/HTTP2Tests/*` | ◐ parsed, not scheduled |
| [3629](rfc3629.txt) | UTF-8 | text-frame / close-reason validation | `Sources/WebSocket/WebSocketConnection.swift` (`isValidUTF8`) | `Tests/WebSocketTests/*` | ✅ |
| [5234](rfc5234.txt) | ABNF | grammar notation used by every parser | (reference) | — | n/a (reference) |

---

## Superseded predecessors (linked, not vendored)

These are obsoleted by the vendored set above; kept as links for historical cross-reference only.

- **HTTP/1.1 (2014):** [7230](https://www.rfc-editor.org/rfc/rfc7230) · [7231](https://www.rfc-editor.org/rfc/rfc7231) · [7232](https://www.rfc-editor.org/rfc/rfc7232) · [7233](https://www.rfc-editor.org/rfc/rfc7233) · [7234](https://www.rfc-editor.org/rfc/rfc7234) · [7235](https://www.rfc-editor.org/rfc/rfc7235) → obsoleted by 9110/9111/9112.
- **HTTP/2 (2015):** [7540](https://www.rfc-editor.org/rfc/rfc7540) → obsoleted by 9113. (HPACK 7541 remains current.)
- **HTTP/1.1 (1999):** [2616](https://www.rfc-editor.org/rfc/rfc2616) → obsoleted by the 723x series, then by 911x.

## Provenance & reproducibility

All files fetched 2026-06-24 from `rfc-editor.org`. `Standards/fetch.sh` re-downloads the exact set; run it
to refresh or to verify integrity in CI. Errata are not snapshotted — consult
`https://www.rfc-editor.org/errata/rfcNNNN` for the live list.
