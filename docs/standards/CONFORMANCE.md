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

### Why the external tool is not the gate — measured, 2026-07-31

Earlier revisions of this document said the 48/49 failures were "every one a QUIC-transport-layer
expectation aimed at Apple's closed Network.framework stack". That did not survive re-measurement
(arm64 macOS, h3spec v0.1.13 `h3spec-mac-arm64`, release `httpd-example`):

- **h3spec *can* be split.** It accepts hspec's `-m/--match` and `-s/--skip`, and its 49 cases are
  grouped `describe "QUIC servers"` (34 — 27 RFC 9000 transport + 7 RFC 9001 TLS) and
  `describe "HTTP/3 servers"` (15 — 11 RFC 9114 + 4 RFC 9204). `-m "HTTP/3 servers"` selects exactly
  the subset that exercises this repository's code. The split is mechanically available.
- **The split still cannot gate.** A full re-run reproduces 49 examples / 48 failures, and every one
  of the 48 carries the *identical* message `did not get expected exception: QUICException`. The 15
  HTTP/3-layer cases fail for the same reason as the 34 transport ones. Under `-d` the cause is
  `ConnectionIsTimeout "Client Handshaking"` — nothing ever reaches the HTTP/3 layer. A deliberately
  broken H3 engine would produce a byte-identical report: zero discriminating power.
- **The cause is not Apple's QUIC stack.** `ModernQUICTransport.start` constructs its
  `Network.NetworkListener` with no port, so the QUIC listener binds an **ephemeral UDP port** and
  only announces it through `Alt-Svc` (observed `alt-svc: h3=":50649"` while the job dialed 14433).
  h3spec has no `Alt-Svc` discovery — it dials the UDP port you give it. The job has been probing a
  port with no listener on it. Dialing the bound port directly does not rescue the run either: a real
  h3 client (curl 8.21, ngtcp2/nghttp3, `--http3-only`) also fails to connect to it, so the QUIC
  listener is not currently reachable from an external client on this host. That is a transport
  defect, and it is also why `bench-h3load` has never produced a number.

### The excluded checks, by name

The 34 excluded cases are listed individually — section, behavior, and expected error code — in
`Tests/Protocols/HTTP3Tests/Conformance/H3Catalog+Transport.swift` (the 27 RFC 9000 rows) and the
`quicTLS` block of `H3ConformanceCatalog.swift` (the 7 RFC 9001 rows). Each is `.platform`-stamped:
enforced by Apple's QUIC/TLS implementation beneath the engine, with no code in this repository able
to affect the outcome. `H3SpecTests` asserts that stamping is exhaustive, so a case cannot be
excluded by forgetting it.

### Promotion trigger

Fix the QUIC listener to bind the port it is given, then re-run
`h3spec … -m "HTTP/3 servers"`. If those 15 cases become meaningful, promote that step of
`h3spec-observation` to a required job alongside `h3-conformance` — the two would then check the
same MUSTs from opposite sides (in-process engine vs. over-the-wire), which is worth having. The
34 transport/TLS cases stay excluded regardless; they test code this project does not own.

## HTTP/3 load (h3load)

**Deferred — no portable tool.** There is no standard "h2load for HTTP/3"; a load lane needs either a
bespoke driver over the Network.framework QUIC client (Darwin-only, benchmark-only) or a vendored
quiche/lsquic client. Tracked as a benchmark-matrix follow-up.
