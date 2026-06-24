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
| generic | sanity / framing | 43 / 44 (1 fail — invalid preface) |
| http2/3 | starting HTTP/2 (preface) | 1 / 2 (1 fail — invalid preface) |
| http2/4 | frame format | **9 / 9** ✅ |
| http2/5 | streams & multiplexing | **blocked** — 5.1.2 hangs (see Finding 2) |
| http2/6 | frame definitions | **42 / 42** ✅ |
| http2/7 | GOAWAY | **2 / 2** ✅ |
| http2/8 | HTTP message exchanges | **18 / 18** ✅ |
| hpack | HPACK (RFC 7541) | **8 / 8** ✅ |

**Summary:** of the 125 tests outside the streams section, **123 pass**; the 2 failures are the same
invalid-preface case (Finding 1). Section 5 cannot complete because test 5.1.2 hangs (Finding 2).

**CI gate scope:** the `h2spec` job gates on `http2/4 http2/6 http2/7 http2/8 hpack` (79 tests, all
passing, fast) under a hard `timeout`, so a regression there fails the build. `generic`, `http2/3`, and
`http2/5` are excluded until Findings 1 & 2 are fixed — then fold them into the gate.

### Finding 1 — no GOAWAY on an invalid connection preface (low)

RFC 9113 §3.4 / §5.4.1: an invalid client connection preface is a connection error of type
`PROTOCOL_ERROR`, which should emit a `GOAWAY` before the connection closes. The server detects the
bad preface and closes the TCP connection (the engine queues `GOAWAY` at `HTTP2Connection.swift`
`receive`, the server flushes it at `HTTPServer.swift:190`), but h2spec observes `unexpected EOF` —
the peer is closed without the `GOAWAY` reaching the wire. Likely a protocol-sniff routing or
flush-before-close ordering issue. Impact is low (the connection *is* terminated; only the diagnostic
frame is missing), so it is tracked rather than rushed.

### Finding 2 — `SETTINGS_MAX_CONCURRENT_STREAMS` not advertised/enforced (medium — reliability/DoS)

`h2spec http2/5.1.2` (Stream Concurrency) **hangs**: it opens more concurrent streams than the
advertised limit and waits for the server to refuse the excess (`REFUSED_STREAM` / `PROTOCOL_ERROR`,
RFC 9113 §5.1.2). The server neither advertises a `SETTINGS_MAX_CONCURRENT_STREAMS` bound nor refuses
the excess stream, so h2spec waits indefinitely. Beyond the test hang, **unbounded concurrent streams
is a memory-exhaustion vector** (each open stream allocates state) — a real reliability/DoS concern.
Recommended fix: advertise a finite `SETTINGS_MAX_CONCURRENT_STREAMS` and reject an inbound HEADERS
that would exceed it with `RST_STREAM(REFUSED_STREAM)`. Deserves its own change with regression tests
(an `H2Wire`-driven over-limit scenario) — not an end-of-session patch.

## WebSocket — Autobahn TestSuite (RFC 6455)

Not yet wired. The recommended approach is the `crossbario/autobahn-testsuite` Docker image driving a
`fuzzingclient` against `httpd-example`'s `/ws` echo endpoint, failing on any non-`OK`/`INFORMATIONAL`
case. Deferred: the CI image has no Docker, and the in-house WebSocket suites + the new
`WebSocketFuzzTests` already exercise framing, masking, fragmentation, close codes, and UTF-8.
