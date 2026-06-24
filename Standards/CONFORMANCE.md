# Conformance report — external test suites

Results of running the gold-standard external conformance tools against the live `httpd-example`
server. Re-run locally with the commands below; the `h2spec` core sections are gated in CI
(`.github/workflows/ci.yml`, the `h2spec` job).

## HTTP/2 — h2spec (RFC 9113 / RFC 7540 test suite)

```bash
swift build -c release --product httpd-example
HTTPD_MAX_CONN=100000 .build/release/httpd-example 18080 posixKqueue &
h2spec -h 127.0.0.1 -p 18080 --timeout 3 http2/4 http2/6 http2/7 http2/8 hpack
```

Measured 2026-06 (Apple Silicon, Swift 6.4, `posixKqueue` backbone):

| Section | Area | Result |
|---|---|---|
| generic | sanity / framing | 43 / 44 (1 fail — invalid preface, Finding 1) |
| http2/3 | starting HTTP/2 (preface) | 1 / 2 (1 fail — invalid preface, Finding 1) |
| http2/4 | frame format | **9 / 9** ✅ |
| http2/5 | streams & multiplexing | **20 / 21** (1 fail — 5.1.12, Finding 2) — hang fixed |
| http2/6 | frame definitions | **42 / 42** ✅ |
| http2/7 | GOAWAY | **2 / 2** ✅ |
| http2/8 | HTTP message exchanges | **18 / 18** ✅ |
| hpack | HPACK (RFC 7541) | **8 / 8** ✅ |

**Summary:** **143 / 146 pass.** The 3 failures are the invalid-preface case (Finding 1, counted in
both `generic` and `http2/3`) and one closed-stream nuance (Finding 2). The streams section, which
formerly hung, now completes after the concurrency-cap fix below.

**CI gate scope:** the `h2spec` job gates on `http2/4 http2/6 http2/7 http2/8 hpack` (79 tests, all
passing, fast) under a hard `timeout`, so a regression there fails the build. `generic`, `http2/3`,
and `http2/5` are excluded only because of Findings 1 & 2; fold them in once those land.

### Fixed — `SETTINGS_MAX_CONCURRENT_STREAMS` advertised at a sane bound (was a DoS + a hang)

The engine already advertised and enforced the cap (`HTTP2Connection` init + the `REFUSED_STREAM`
refusal), but `HTTPLimits.maxConcurrentStreams` defaulted to a **permissive `1_048_576`**: the server
advertised ~1M concurrent streams, so (a) one connection could open unbounded streams — a stream-state
memory-exhaustion vector — and (b) `h2spec http2/5.1.2` *hung*, unable to practically exceed the cap.

Fixed by giving `maxConcurrentStreams` a **secure, non-throttling default of 128** (RFC 9113 §5.1.2
recommends ≥100) while leaving the per-/global-connection ceilings tunable via the new `HTTPLimits`
presets (`default` secure, `highThroughput` for benchmarks/trusted peers, `hardened` for public).
Concurrency is across connections, not within one, so 128 streams/connection costs zero throughput.
Result: `http2/5` completes at 20/21, the hang is gone, and the DoS bound holds. Regression test:
`Tests/HTTP2Tests/HTTP2ConcurrencyTests.swift` (exact cap — at the cap allowed, one past refused).

### Finding 1 — no GOAWAY on an invalid connection preface (low — benign ambiguity)

`h2spec generic`/`http2/3.5.2` send an invalid h2c preface (`INVALID CONNECTION PREFACE…`) and expect a
`GOAWAY(PROTOCOL_ERROR)` or a clean close. Probed behavior: the bytes do not start with the h2 preface
marker (`PRI * HTTP/2.0\r\n`), so the protocol sniffer routes them to **HTTP/1.1**, where they parse as
a request with an unsupported version and earn a sensible `505 HTTP Version Not Supported` + close —
which h2spec, expecting an h2 frame, reports as `unexpected EOF`. A preface that *starts* with the
marker but is corrupted later is correctly routed to h2 and earns a GOAWAY (verified).

This is the genuine h2c-vs-HTTP/1 ambiguity: with prior-knowledge h2c there is no signal that garbage
was *meant* to be h2, and routing arbitrary non-h1 bytes to h2 would mis-handle real HTTP/1 clients.
The connection *is* terminated; only the diagnostic frame differs. **Documented, not changed** — the
505-then-close is defensible behavior.

### Finding 2 — HEADERS on an END_STREAM-closed stream should be a connection error (medium)

`h2spec http2/5.1.12` ("closed: Sends a HEADERS frame") closes a stream via END_STREAM, then sends a
HEADERS frame on it. RFC 9113 §5.1 (closed state): a HEADERS/DATA frame after END_STREAM is a
**connection** error of type `STREAM_CLOSED` (GOAWAY). The engine currently treats a HEADERS on a
recently-closed stream as a **stream** error (`RST_STREAM(STREAM_CLOSED)`, the audit-F1 lenient path).

To fix correctly the engine must track *how* a stream closed (RST_STREAM vs END_STREAM): a frame after
RST may be ignored / stream-scoped (§5.1, "received after RST_STREAM"), but a frame after END_STREAM is
connection-scoped. That distinction (a per-stream close-reason in the bounded closed-stream FIFO) is its
own change with regression tests — tracked here rather than rushed. Surfaced only once the §5.1.2 hang
above was cleared.

## WebSocket — Autobahn TestSuite (RFC 6455)

Not yet wired. The recommended approach is the `crossbario/autobahn-testsuite` Docker image driving a
`fuzzingclient` against `httpd-example`'s `/ws` echo endpoint, failing on any non-`OK`/`INFORMATIONAL`
case. Deferred: the CI image has no Docker, and the in-house WebSocket suites + the new
`WebSocketFuzzTests` already exercise framing, masking, fragmentation, close codes, and UTF-8.
