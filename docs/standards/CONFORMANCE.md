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
  it to `close(errorCode:)`. What happens next is a platform limitation, established 2026-08-16 by
  the experiment matrix below: **Network.framework provides no way to choose the application error
  code of a CONNECTION_CLOSE** (RFC 9000 §10.2, frame type 0x1d §19.19).

Real third-party HTTP/3 works: `curl --http3-only` gets `HTTP/3 200` on `GET /` and on
`POST /echo` against `httpd-example 14433 networkFramework tls`.

### The connection-close code is not expressible on Apple's stack — measured, 2026-08-16

The 2026-08-02 note above this one recorded a dead end: "setting `applicationError` before teardown
makes Network.framework stop closing the connection at all — 15 failures / 60 s of timeouts on both
backbones". That symptom was real but the reading was wrong. Setting
`NWProtocolQUIC.Metadata.applicationError` (or the modern `NetworkConnection<QUIC>.applicationError`)
with a `nil` reason string **segfaults** — `nw_quic_set_application_error` ends in
`String(cString:)` → `strlen(NULL)` (crash report: `swiftpm-testing-helper`, EXC_BAD_ACCESS at 0x0,
faulting frame `nw_quic_set_application_error + 120`). A crashed server times out every subsequent
h3spec case on whichever backbone is selected, which is exactly the "stops closing, both backbones"
signature. With a non-`nil` reason there is no crash and no stall — and no code on the wire either.

Everything below was measured on arm64 macOS 27.0 (SDK 27), h3spec v0.1.13, with the wire also
observed by a second Network.framework client (`QUICApplicationCloseProbe` in `HTTPTransportTests`,
which reads `nw_quic_get_application_error` — "the value received from the peer", `UInt64.max` when
none arrived):

- **The write lands; nothing reads it.** After `applicationError = .init(code:reason:)`, a *fresh*
  `metadata(definition:)` copy reads the code back — the value is in live, shared QUIC state. Every
  teardown path then ignores it:
  - modern (`NetworkConnection<QUIC>`, structured teardown — the API's only close): emits
    CONNECTION_CLOSE 0x1d with a **hardwired code 0** (h3spec: `ApplicationProtocolErrorIsReceived
    (ApplicationProtocolError 0)`), whatever was set;
  - legacy (`NWConnectionGroup.cancel()`): closes **abortively, with no 0x1d frame at all** — the
    peer fails with `ENOTCONN` and reads "no error received";
  - client direction (plain `NWConnection`, set-then-`cancel()`, including pre-arming the error
    right after `.ready`): identical — the peer reads "no error received". The limitation is the
    stack's, not the listener side's.
- **Every other candidate mechanism was tried and does not deliver the code**: setting the error on
  per-stream metadata (any stream, all streams, streams cancelled first, group cancelled first);
  riding it on a final send (legacy `ContentContext(metadata:)`, modern `send(_:metadata:)` builder,
  with and without FIN — the send succeeds, the code never appears; a FIN on the control stream
  additionally provokes the client into closing with H3_CLOSED_CRITICAL_STREAM); letting the modern
  `inboundStreams` handlers throw (resets the streams, closes nothing). The public API surface has
  no other close: `NWConnectionGroup` has no error parameter, the modern `NetworkChannel` has no
  `cancel()` at all, and `quic_options.h` offers exactly `nw_quic_set_application_error` — which the
  close paths do not consult.
- **Stream-level codes DO work.** `nw_quic_set_stream_application_error`
  (`streamApplicationErrorCode`) is honored on RESET_STREAM/STOP_SENDING — it is why the three
  header-validation h3spec cases pass with their mandated H3_MESSAGE_ERROR. Only the
  connection-level close code is inexpressible.
- **The legacy backbone was never part of the 12-failure figure.** Forced onto
  `LegacyQUICTransport`, `-m "HTTP/3 servers"` is 15 examples / **15 failures** in 15.1 s: with no
  0x1d frame ever sent, the 11 cases that at least *see* code 0 on the modern backbone see nothing
  and time out. The 2026-08-02 "h3spec now discriminates" numbers are modern-backbone numbers.

`close(errorCode:)` in both backbones now records the code (with a non-`nil` reason — the crash
guard) and tears down, so the mandated §8.1 code is in the connection's QUIC state if Apple's stack
ever starts consulting it. The premise is **pinned**: `closeCarriesTheApplicationErrorCode` in
`Legacy`/`ModernQUICTransportTests` hard-asserts that the close arrives promptly and crash-free, and
wraps the code assertion in `withKnownIssue` — the day an SDK delivers the code, the known issue
stops reproducing, the test flags it, and the rows below can be lifted.

### The h3spec rows blocked by that platform limitation, by name

The following 11 `-m "HTTP/3 servers"` cases fail **only** because the mandated connection-close
code cannot be put on the wire — the engine detects each violation and closes the connection (h3spec
receives the close as `ApplicationProtocolError 0` on the modern backbone), and
`endpointClosesWithMandatedError` in the gating `h3-conformance` job proves the engine selects the
mandated code for every one of them. Platform-blocked in the same sense as the `.platform`-stamped
QUIC-transport rows:

| h3spec case | Mandated code (RFC 9114 §8.1 / RFC 9204 §6) |
|---|---|
| DATA received before HEADERS [HTTP/3 4.1] | H3_FRAME_UNEXPECTED (0x0105) |
| first control frame is not SETTINGS [HTTP/3 6.2.1] | H3_MISSING_SETTINGS (0x010A) |
| DATA frame on a control stream [HTTP/3 7.2.1] | H3_FRAME_UNEXPECTED (0x0105) |
| HEADERS frame on a control stream [HTTP/3 7.2.2] | H3_FRAME_UNEXPECTED (0x0105) |
| second SETTINGS frame [HTTP/3 7.2.4] | H3_FRAME_UNEXPECTED (0x0105) |
| HTTP/2 settings included [HTTP/3 7.2.4.1] | H3_SETTINGS_ERROR (0x0109) |
| CANCEL_PUSH in a request stream [HTTP/3 7.2.5] | H3_FRAME_UNEXPECTED (0x0105) |
| invalid static table index [QPACK 3.1] | QPACK_DECOMPRESSION_FAILED (0x0200) |
| dynamic table capacity over limit [QPACK 4.1.3] | QPACK_ENCODER_STREAM_ERROR (0x0201) |
| control stream closed [QPACK 4.2] | H3_CLOSED_CRITICAL_STREAM (0x0104) |
| Insert Count Increment is 0 [QPACK 4.4.3] | QPACK_DECODER_STREAM_ERROR (0x0202) |

The 12th failure — `H3_MESSAGE_ERROR if mandatory pseudo-header fields are absent [HTTP/3 4.1.3]`,
"did not get expected exception" — is **not** platform-blocked: its two sibling 4.1.3 cases pass via
stream-level H3_MESSAGE_ERROR, so this one is an engine-side gap and stays owned here.

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

**Not met — and no longer pending on this repository's code.** `h3spec … -m "HTTP/3 servers"`
remains 15 examples / 12 failures on the modern backbone (34 / 4 on `-m "QUIC servers"`,
unchanged). Of the 12, the 11 named above are blocked by the platform's inexpressible
connection-close code, and 1 is an engine-side gap (4.1.3, mandatory pseudo-headers). A promoted
gate would therefore be able to enforce at most the 3 currently-passing cases, which is not a gate
worth a required job. Promote when either (a) the pinned `closeCarriesTheApplicationErrorCode`
probes flag that an SDK started delivering the recorded code, or (b) the 4.1.3 engine gap is closed
*and* a skip-list gating run is judged worth its maintenance. Until then the in-repo
`h3-conformance` job remains the gate, unweakened — it asserts the very codes the platform drops,
at the engine seam. The 34 transport/TLS cases stay excluded regardless; they test code this
project does not own.

## HTTP/3 load (h3load)

**Deferred — no portable tool.** There is no standard "h2load for HTTP/3"; a load lane needs either a
bespoke driver over the Network.framework QUIC client (Darwin-only, benchmark-only) or a vendored
quiche/lsquic client. Tracked as a benchmark-matrix follow-up.
