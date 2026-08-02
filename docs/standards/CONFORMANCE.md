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
| http2/5 | streams & multiplexing | **21 / 21** ✅ (hang + 5.1.12 fixed) |
| http2/6 | frame definitions | **42 / 42** ✅ |
| http2/7 | GOAWAY | **2 / 2** ✅ |
| http2/8 | HTTP message exchanges | **18 / 18** ✅ |
| hpack | HPACK (RFC 7541) | **8 / 8** ✅ |

**Summary:** **144 / 146 pass.** The only 2 failures are the invalid-preface case (Finding 1, counted in
both `generic` and `http2/3`) — a benign h2c/HTTP-1 ambiguity. Every other section is 100%, including the
streams section, which formerly hung and now passes fully (the two fixes below).

**CI gate scope:** the `h2spec` job gates on `http2/4 http2/5 http2/6 http2/7 http2/8 hpack` (100 tests,
all passing, fast) under a hard `timeout`, so a regression there fails the build. Only `generic` and
`http2/3` are excluded, for the invalid-preface case (Finding 1).

**Backbone parity:** the gated 100-test set passes **100/100 against all four transport backbones**
(`networkFramework`, `posixKqueue`, `posixDispatch`, `swiftSystem`) — the sans-I/O engine is shared, and
each backbone's distinct flush/close timing still delivers correct framing, resets, and GOAWAY
(`networkFramework` serves h2c with no TLS). The CI gate runs one backbone (`posixKqueue`) for speed;
conformance is transport-independent.

### Fixed — `SETTINGS_MAX_CONCURRENT_STREAMS` advertised at a sane bound (was a DoS + a hang)

The engine already advertised and enforced the cap (`HTTP2Connection` init + the `REFUSED_STREAM`
refusal), but `HTTPLimits.maxConcurrentStreams` defaulted to a **permissive `1_048_576`**: the server
advertised ~1M concurrent streams, so (a) one connection could open unbounded streams — a stream-state
memory-exhaustion vector — and (b) `h2spec http2/5.1.2` *hung*, unable to practically exceed the cap.

Fixed by giving `maxConcurrentStreams` a **secure, non-throttling default of 128** (RFC 9113 §5.1.2
recommends ≥100) while leaving the per-/global-connection ceilings tunable via the new `HTTPLimits`
presets (`default` secure, `highThroughput` for benchmarks/trusted peers, `hardened` for public).
Concurrency is across connections, not within one, so 128 streams/connection costs zero throughput.
Result: the hang is gone and the DoS bound holds. Regression test:
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

### Fixed — HEADERS reusing an END_STREAM-closed stream is now a connection error

`h2spec http2/5.1.12` ("closed: Sends a HEADERS frame") closes a stream via END_STREAM, then sends a
HEADERS frame on it. RFC 9113 §5.1: a HEADERS reusing an END_STREAM-closed id (which cannot reopen) is a
**connection** error `STREAM_CLOSED` (GOAWAY). The engine had treated it as the audit-F1 lenient *stream*
error — correct only for an RST-closed id.

Fixed by tracking *how* each stream closed in the bounded closed-stream FIFO (`HTTP2Connection`'s
`StreamCloseReason` = `.endStream` / `.reset`): a HEADERS reuse of an END_STREAM-closed id is now a
connection error, while an RST-closed id (and any late DATA on either) keeps the survivable stream error
(F1). `http2/5` is now 21/21. Regression test: `H2SpecStreamTests.closedStreamHeadersIsConnectionError`.

## WebSocket — Autobahn TestSuite (RFC 6455)

**Gating.** The `autobahn` CI job (`.github/workflows/ci.yml`, on `ubuntu-latest` — which,
unlike the macOS image, has Docker) runs the `crossbario/autobahn-testsuite` `fuzzingclient` against
`httpd-example`'s `/ws` echo: the server runs in the Swift container on the host network, Autobahn runs as
its own container against it, and `.github/conformance/autobahn/check.py` fails the run on any `FAILED`
case (config: `.github/conformance/autobahn/fuzzingclient.json`). The in-house WebSocket suites + `WebSocketFuzzTests`
(framing, masking, fragmentation, close codes, UTF-8) remain the always-on coverage.

## HTTP/3 / QUIC — RFC 9114 / RFC 9204 (and what h3spec can and cannot do)

**Gated in-repo (`h3-conformance`, required); external h3spec is dispatch-only evidence.**

The gate is the `HTTP3Tests` / `QPACKTests` suites plus the real-QUIC loopback in
`HTTPServerHTTP3Tests`, run in release by the `h3-conformance` job. `H3SpecTests` mirrors h3spec's
catalog row-for-row: `catalogIsWellFormed` pins the per-layer split (27 RFC 9000 + 7 RFC 9001 +
11 RFC 9114 + 4 RFC 9204 = 49) so the mirror cannot silently narrow, and
`endpointClosesWithMandatedError` drives each engine-layer row against a fresh `HTTP3Connection` and
asserts the mandated error code (honoring the RFC 9114 §8 generic-error tolerance). An HTTP/3
regression fails that job.

### Why the external tool is not the gate — measured, 2026-08-02

This section has now been wrong twice, in opposite directions, so it states what was measured and how.

The 2026-07-31 revision blamed the ephemeral QUIC listener port. That was **a** defect and it is
fixed — but it was not the one keeping every client out, and the "not Apple's QUIC stack" conclusion
it drew was reached from a run that never got a packet to the server. Re-measured on arm64 macOS 27,
h3spec v0.1.13 `h3spec-mac-arm64`, release `httpd-example`, curl 8.21.0 (ngtcp2 1.25.0 /
nghttp3 1.18.0, OpenSSL 3.6.3):

- **The real blocker was ALPN, on both backbones.** `TransportTLS.applicationProtocols` is one list
  shared by the TCP TLS listener and the QUIC listener, and its documented default is the TCP set
  `["h2", "http/1.1"]`. Both QUIC backbones fed that list straight to their QUIC listener, so the
  listener advertised `h2`/`http/1.1` over QUIC and **never `h3`** (RFC 9114 §3.1). Any client
  offering only `h3` shared no protocol with us, and RFC 9001 §8.1 makes that terminal. Measured
  directly with a Network.framework probe against the running example server: a client offering
  `["h2"]` reached `.ready` and reported `negotiatedALPN = h2`; a client offering `["h3"]` never
  completed. See `Sources/Transport/HTTPTransport/Quic/QUICApplicationProtocols.swift`.
- **It was never a modern-vs-legacy difference.** An earlier note claimed the legacy backbone
  completed the QUIC handshake where the modern one did not. It does not: forced onto
  `LegacyQUICTransport`, the same binary produced the same 15/15
  `TransportErrorIsReceived TLSInternalError` in 0.056 s that the modern backbone produced in
  0.064 s. Both backbones read the same ALPN list, so both had the same defect.
- **Apple's stack sends the wrong alert, which is why this looked like a server crash.** RFC 9001
  §8.1 mandates `no_application_protocol` (TLS alert 120, QUIC error `0x178`) when no application
  protocol is negotiated. Network.framework sends `internal_error` (alert 80, QUIC error `0x150`)
  instead. That deviation is what sent three separate investigations looking for a fault in
  certificate handling, transport parameters and TLS-version pinning rather than at ALPN.
- **h3spec now discriminates, and now fails on this repository's own code.** Post-fix:
  `-m "HTTP/3 servers"` is 15 examples / **12 failures** in 2.3 s (3 pass), and `-m "QUIC servers"`
  is 34 examples / **4 failures** in 8.6 s (was 34/34). The HTTP/3-layer failures are real engine
  findings, not handshake noise — the dominant one is that the connection is closed with QUIC
  application error code **0** instead of the RFC 9114 §8.1 code the engine selected.
- **The error code is dropped by the transport, not by the engine.** The engine already emits
  `.closeConnection(code)` with the right §8.1 code and `HTTPServer+HTTP3Dispatch` already forwards
  it, but both backbones' `close(errorCode:)` discarded the argument. The obvious fix does **not**
  work and was measured, not assumed: setting `NetworkConnection<QUIC>.applicationError` (modern) or
  the connection group's `NWProtocolQUIC.Metadata.applicationError` (legacy) before teardown makes
  Network.framework stop closing the connection **at all** — h3spec goes from 12 failures in 2.3 s to
  15 failures in 60.1 s, every one a timeout, on both backbones. Whatever the right sequence is, it
  is not "set the error then tear down"; this is a live follow-up, not a solved problem.

Real third-party HTTP/3 works: `curl --http3-only` gets `HTTP/3 200` on `GET /` and on
`POST /echo` against `httpd-example 14433 networkFramework tls`.

### The excluded checks, by name

The 34 excluded cases are listed individually — section, behavior, and expected error code — in
`Tests/Protocols/HTTP3Tests/Conformance/H3Catalog+Transport.swift` (the 27 RFC 9000 rows) and the
`quicTLS` block of `H3ConformanceCatalog.swift` (the 7 RFC 9001 rows). Each is `.platform`-stamped:
enforced by Apple's QUIC/TLS implementation beneath the engine, with no code in this repository able
to affect the outcome. `H3SpecTests` asserts that stamping is exhaustive, so a case cannot be
excluded by forgetting it.

The `.platform` stamping now has evidence behind it that it did not have before: with a reachable,
correctly-negotiating listener, 30 of those 34 cases **pass** on Apple's stack. The 4 that do not
(RFC 9000 §12.4 unknown frame type, §12.4 no frames, §19.7 NEW_TOKEN, §19.11 invalid MAX_STREAMS) are
Network.framework's own transport behavior and remain unaffectable from here. The earlier 34/34-fail
reading was an artifact of a handshake that never completed.

### Promotion trigger

**Not met.** With the listener reachable and `h3` negotiated, `h3spec … -m "HTTP/3 servers"` is
15 examples / 12 failures — the cases are now meaningful, which is the improvement, but they are
failing on this repository's code. Promote that step of `h3spec-observation` to a required job when
those 12 go green; the dominant blocker is the dropped RFC 9114 §8.1 connection-close error code
described above. Until then the in-repo `h3-conformance` job remains the gate, unweakened. The 34
transport/TLS cases stay excluded regardless; they test code this project does not own.

## HTTP/3 load (h3load)

**Deferred — no portable tool.** There is no standard "h2load for HTTP/3"; a load lane needs either a
bespoke driver over the Network.framework QUIC client (Darwin-only, benchmark-only) or a vendored
quiche/lsquic client. Tracked as a benchmark-matrix follow-up.
