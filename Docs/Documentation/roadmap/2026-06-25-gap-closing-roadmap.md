# HTTP Server — Gap-Closing Roadmap (production readiness)

Durable, in-repo tracker for closing the feature gaps found in the
[server feature gap analysis](../audit/2026-06-25-server-feature-gap-analysis.md) (gaps **G0–G7**). It
takes the server from a *feature-rich, security-ahead Apple-platform app-server library* to a *deployable,
production-grade origin app server*. It **continues** the
[completion roadmap](2026-06-25-completion-roadmap.md) (P0–P11) rather than replacing it — protocol-tail
items (G6) and observability (G1) already live there as P8/P9/P10 and are cross-referenced, not
duplicated.

Same rules as the completion roadmap: sequential on `main`, no worktrees, each phase lands behind the
project gates — **build + full tests + ASan/fuzz on touched paths + swift-format/SwiftLint `--strict`,
signed commit**. Tick a box only when its gate is green and committed.

Baseline: `main`, 846 tests green (per the completion roadmap change log).

## Legend
- [ ] not started · [~] in progress · [x] done (gate green + committed)
- **Effort:** S ≤2d · M ~1wk · L ~2–3wk · XL ~1mo+ · **Risk:** ▲ high (conformance/security/concurrency) · ■ medium · ● low

## Scope & the one framing rule

We are an **origin application server**, not an edge reverse proxy. This roadmap closes the gaps that a
*complete app server* is expected to have. It explicitly does **not** build edge-proxy features
(reverse proxy, load balancing, ACME, OCSP, edge caching, WAF) — those are composed by putting nginx /
Caddy / Envoy in front. See [Non-goals](#non-goals).

## Recommended sequencing (waves)

Ordered by value-per-risk, with the big parallelizable item (G0) running as its own track. Each wave is
independently shippable.

| wave | phases | theme | why here |
|---|---|---|---|
| **W1** | G2, G5, G7, G1 | response-side + ops surface | low-risk, high-value, mostly additive middleware/modules; ship fast |
| **W2** | G3, G4 (+SNI) | transport/TLS hardening | medium risk; touches the TLS path; do as one focused effort |
| **W3** | **G0** | Linux deployability | XL; the single biggest gap; runs as a **parallel long-lived track** from day 1 |
| **W4** | G6 | protocol-tail completion | ▲ conformance-sensitive; continue P8/P6b/P10 with fresh context |

> **Start G0 immediately and in parallel.** It is the longest pole and unblocks real deployment; W1/W2
> proceed on the Apple path meanwhile, and each W1/W2 feature must be written **portably** (no new
> Network.framework-only assumptions) so it lands on Linux for free when G0 arrives.

---

## W1 — Response-side & operations surface

### [~] G2 — Outbound Brotli (+ Zstd) · Effort M · Risk ● — *Darwin shipped; Zstd deferred (D2), Linux shim → G0*
We decode `br`/`deflate`/`gzip` inbound (P4) but only *emit* gzip. Close the asymmetry.
- [x] Brotli encoder behind `CompressionMiddleware` (`Brotli.swift`): Apple's `COMPRESSION_BROTLI`
      **encodes** on Darwin (level-2 — the framework ships the encoder, so **no C shim is needed here**). The
      `libbrotlienc` C shim (pattern: `CCRC32`/`CWSDeflate`) is only for the portable/Linux path → G0.
- [x] Proper `Accept-Encoding` negotiation: q-values, `identity`, ordering preference (br > gzip when both
      accepted), `Vary: Accept-Encoding`, min-size + content-type allowlist (skip already-compressed types).
- [ ] Optional Zstd (`COMPRESSION_ZLIB` has no zstd; gate behind a `libzstd` shim — ship only if cheap)
      — **deferred (D2)**: Brotli-out covers the table-stakes case.
- _Gate:_ per-codec round-trip + negotiation tests (br chosen over gzip, q=0 exclusion, identity
      fallback), streaming responses still skip compression, decompression-bomb caps unaffected; ASan clean.
      ✓ green: `CompressionMiddlewareTests` — 14 cases incl. the Brotli (RFC 7932) round-trip; ASan + lint clean.

### [~] G5 — Static-serving completeness · Effort M · Risk ● — *responder-level shipped; sendfile → transport phase*
`FileResponder` (P7) does range/conditional/ETag/streaming; add the production niceties.
- [x] **Precompressed sidecars:** serve `foo.css.br` / `foo.css.gz` when the client accepts that coding and
      the sidecar exists and is no older than the original; sets `Content-Encoding` + `Vary` + coding-ETag.
      Never for a `Range` (identity only). (`FileResponder+Precompressed.swift`.)
- [x] **Directory autoindex** (opt-in): traversal-safe HTML listing (name/size/mtime, sorted), every entry
      name HTML-escaped (XSS-safe), dotfiles omitted; **off by default**. (`FileResponder+Autoindex.swift`.)
- [ ] **`sendfile`/zero-copy** — **deferred to a transport-layer phase**: every `TransportConnection` is
      `send([UInt8])`-only with a private fd, so `sendfile(2)` needs a new protocol method across all 4
      backbones + h1/h2/h3 plumbing. The streamed path already bounds memory (64 KiB chunks), so this is an
      optimization, not a gap.
- [x] **`try_files`-style fallback** chain (SPA hosting: a missing path serves the configured `fallback`,
      e.g. `index.html`).
- _Gate:_ sidecar chosen only when fresh + accepted (skipped when stale / ranged / unaccepted), autoindex
      traversal-safe + off-by-default + HTML-escaped, fallback resolves; HEAD/range/conditional/403 unaffected.
      ✓ green: `FileResponderTests` — 14 cases (8 prior + 6 new); ASan + lint clean.

### [x] G7 — Auth building blocks · Effort M · Risk ■ — *new isolated `HTTPAuth` module*
We ship signed sessions only. Add the verification primitives (keep OAuth/OIDC *flows* out — app concern).
All three live in a new isolated **`HTTPAuth`** module so swift-crypto (and its `_CryptoExtras` BoringSSL
graph) stays out of a bare-server consumer's resolved graph. Surfaces the verified principal on the new
`.xAuthSubject` field (a richer claims-context object is a separate enhancement — the request is
header-only).
- [x] **`BasicAuthMiddleware`** (RFC 7617): realm, constant-time verify (closure or a bundled fixed
      credential via double-HMAC), `401` + `WWW-Authenticate: Basic`, never logs credentials.
- [x] **`JWTMiddleware`** + the `JWT` verify core: **HS256/ES256/RS256** via swift-crypto, validates
      `exp`/`nbf`/`aud`/`iss`; the verifier is bound to one algorithm, so `alg:"none"` and an algorithm
      mismatch are rejected before any key is touched (the confusion defense). Static key (D4 — static
      first; remote JWKS deferred). Asserts `sub` on `.xAuthSubject`.
- [x] **`ForwardAuthMiddleware`** (`auth_request`/`forward_auth` escape hatch): an **injected closure**
      decides allow (propagating chosen headers) / deny — the app owns the subrequest (the server has no
      HTTP client).
- _Gate:_ basic accept/reject + constant-time, JWT valid/expired/bad-sig/wrong-aud + alg-confusion (`none`/
      HS-vs-RS) rejected, forward-auth allow/deny + header propagation; no credential leakage in logs.
      ✓ green: `HTTPAuthTests` — 21 cases (HS/ES/RS256, exp/nbf/aud/iss, `none` + HS-vs-ES confusion,
      Basic, forward-auth); ASan + lint clean.

### [x] G1 — Observability bridges · Effort M · Risk ● — *continues completion-roadmap P9*
A clean `HTTPMetrics` seam + closure logging exist; ship the exporters as an isolated module.
- [x] **`Sources/HTTPObservability/`** isolated module (new deps confined to it): a swift-log structured
      access sink + a swift-metrics `HTTPMetrics` sink with a **Prometheus text exporter** (`/metrics`)
      (G1a) and a swift-distributed-tracing **`.server` span per request** with OTel attributes (G1b).
      (Metrics use method×status labels only — never the path — bounding cardinality and sidestepping
      swift-prometheus CVE-2024-28867.)
- [x] **W3C trace-context**: `traceparent`/`tracestate` extracted inbound via an `Extractor` over
      `HTTPFields`, the span context propagated task-locally on the request (so an instrumented call in a
      handler inherits it). Outbound *injection* is N/A here — the server makes no upstream calls (a client
      concern); deferred until one exists.
- [x] **Built-in `/healthz` + `/readyz`** handlers (liveness/readiness), drain-aware via a `ReadinessProbe`
      the app flips on graceful shutdown (readyz → 503).
- _Gate:_ bridge tests (log line shape, Prometheus exposition parse, span open/close + trace-context
      round-trip, readyz flips on shutdown); **core targets' dependency lists unchanged** (deps isolated to
      the bridge module).

---

## W2 — Transport & TLS hardening

### [~] G3 — mTLS / client certificates · Effort M · Risk ■ — *Darwin shipped; `.optional` + SAN/chain → G0*
Network.framework exposes client-cert challenge + verify blocks; surface them.
- [x] `TransportTLS.clientAuth`: `.none` / `.required` + a `verifyPeer` trust-evaluation hook over the DER
      chain (custom CA / pinning), expressed backbone-agnostically (raw DER, leaf-first) so it ports to the
      G0 BoringSSL path. `.optional` deferred to G0 (Network.framework cleanly does require/none only).
- [x] Surface the **verified client identity** (leaf subject) as the server-asserted `.xClientCertSubject`
      header — the connection→request seam the stack already uses for `.xRequestID`/`.xAuthSubject`,
      stripping any inbound spoof. Full SAN / cert chain is a documented header-only limitation (richer
      request-scoped context → G0, same shape as G7's claims).
- [ ] `SecurityHeadersMiddleware`/docs note on pairing mTLS with auth (follow-up).
- _Gate:_ ✓ required-auth rejects no-cert + pin-rejected cert; pinning hook honored over the DER chain;
      real-loopback integration test with a `DevTLSIdentity` client surfaces its subject; server-stamp test
      strips a spoofed subject and rejects a CR/LF-injecting one (CWE-93). (`.optional` allow-both → G0.)

### [ ] G4 — Graceful config & certificate reload · Effort L · Risk ■
Today a cert rotation or route change needs a restart. Make both hot.
- [ ] **Hot cert reload:** store the TLS identity behind an atomic/`Mutex`; new handshakes pick up the new
      identity, in-flight connections keep theirs (SIGHUP-triggered).
- [x] **Hot responder/route swap:** `HTTPServer.responder` is a `Mutex<any HTTPResponder>` swapped by
      `reloadResponder(_:)`; every dispatch reads it once (never across the `await`), so a request in
      flight finishes on the table it read and new requests use the new one — no drain needed.
- [ ] **SNI multi-cert selection** (sub-gap from the matrix): pick the identity by SNI server-name at
      handshake, so one listener serves multiple host certs.
- _Gate:_ reload under sustained load drops **zero** connections (extend the bench harness with a
      reload-mid-run case), old in-flight requests complete on the old config, SNI picks the right cert.

---

## W3 — Linux deployability (the big one)

### [ ] G0 — Linux support · Effort XL · Risk ▲ — *start now, parallel track*
The single biggest gap: servers run on Linux; we're Apple-only. The sans-I/O engines are already pure and
portable — the lift is the I/O floor and a non-Network.framework TLS path. **Decision required first — see
[Decisions needed](#decisions-needed) D1 (TLS backend).**
- [ ] **`POSIXEpoll` transport backbone** (`Sources/Transport/HTTPTransport/POSIXEpoll/`): epoll readiness
      loop modeled on the existing `KqueueEventLoop`; `SO_REUSEPORT` prefork (already proven on kqueue);
      EINTR/EAGAIN parity; dual-stack IPv6.
- [ ] **Portable TLS path** (D1): a TLS backbone that is *not* Network.framework — BoringSSL/OpenSSL via a
      C shim (NIO-free), reusing the existing ALPN/TLS-1.3-floor/strict-ALPN policy. mTLS (G3) and hot
      reload (G4) must work here too.
- [ ] **Foundation-usage audit:** inventory `Foundation`/`FileManager`/`ProcessInfo`/`JSONSerialization`
      uses; confirm each works under swift-corelibs-foundation or swap to first-party/`ADFoundation`-style
      portable primitives (the library already favors first-party types).
- [ ] **`Synchronization` / atomics:** confirm `Mutex`/`Atomic` availability on the Linux toolchain
      (fallback: swift-atomics) and `ContinuousClock` parity.
- [ ] **HTTP/3:** flag h3 as **Darwin-only in v1** (QUIC is platform-provided via Network.framework); a
      Linux QUIC story (quiche/lsquic shim, or wait for a portable Swift QUIC) is a separate XL follow-up —
      do **not** block Linux h1/h2 on it.
- [ ] **CI:** GitHub Actions `ubuntu-latest` job — build + full suite + ASan; publish the cross-platform
      support matrix in the README.
- _Gate:_ full test suite green on Linux (h1/h2/WS; h3 skipped-with-note), the bench harness runs on Linux,
      ASan clean, no regression on Darwin. Land incrementally: **(a)** epoll backbone + cleartext suite
      green on Linux, **(b)** portable TLS + h2/WS-over-TLS green, **(c)** CI + docs.

---

## W4 — Protocol-tail completion (continues P8 / P6b / P10)

### [~] G6 — Finish the modern-protocol tail · Effort L · Risk ▲ — *continues completion-roadmap P8/P6b/P10*
Engines exist; the conformance-sensitive integration remains. Tracked in the completion roadmap; surfaced
here for completeness.
- [~] **Native HTTP/2 streaming server adoption** (completion P6b/S4): the engine API is done + deadlock-
      proven; server adoption is deferred pending a transport that can stage a late `WINDOW_UPDATE` to prove
      the producer/serve-loop rendezvous deadlock-free. → build that h2 test harness, then adopt.
- [~] **QPACK dynamic-table integration** (completion P8/S5): decoder consumes a peer's dynamic table with
      `QPACK_BLOCKED_STREAMS = 0` first (reject RIC > received inserts), response encoder stays static-only.
- [ ] **WebSocket over HTTP/3** (RFC 9220): extended CONNECT over h3 (we have it on h2 via RFC 8441).
- [x] **HTTP/2 priority scheduling** (RFC 9218) — done (completion P8/S1).
- [ ] **Conformance CI** (completion P10): Autobahn (WS) Docker job, h3spec/QUIC interop, h3 load-client
      wired into the bench matrix.
- _Gate (per item):_ QPACK/h3 conformance + fuzz green; native-h2-streaming deadlock test on the new
      harness; Autobahn green or explicit logged skip; h2spec still green.

---

## Decisions needed

These are forks the team should resolve before the dependent phase starts:

- **D1 — Linux TLS backend (blocks G0 W3-b).** The library is deliberately SwiftNIO-free, so
  `swift-nio-ssl` is off the table. Options: **(a)** a thin BoringSSL C shim (vendored, like the existing C
  shims) — most control, most maintenance; **(b)** system OpenSSL via a C shim — least vendoring, distro
  ABI variance; **(c)** build on swift-crypto's BoringSSL for primitives + a minimal TLS-record binding.
  *Recommendation:* (a) or (c) to keep the dependency posture; decide before W3-b.
- **D2 — Zstd scope (G2).** Ship Zstd-out now (needs a `libzstd` shim) or defer until a consumer asks?
  *Recommendation:* defer; Brotli-out covers the table-stakes case.
- **D3 — Linux QUIC/HTTP/3 (G0 follow-up).** Accept h3 as Darwin-only in v1, or invest in a portable QUIC
  (quiche/lsquic shim) as a dedicated XL track? *Recommendation:* Darwin-only v1; revisit when a portable
  Swift QUIC matures.
- **D4 — JWKS fetching (G7).** Static keys only, or ship a cached remote-JWKS fetcher (adds an HTTP client
  dependency direction)? *Recommendation:* static first; remote JWKS as a follow-up.

## Effort summary

| phase | gap | effort | risk | wave | parallelizable |
|---|---|:--:|:--:|:--:|:--:|
| G2 Brotli/Zstd out | response-side | M | ● | W1 | yes |
| G5 static completeness | response-side | M | ● | W1 | yes |
| G7 auth primitives | security | M | ■ | W1 | yes |
| G1 observability bridges | ops | M | ● | W1 | yes (P9) |
| G3 mTLS | transport | M | ■ | W2 | after/with G4 |
| G4 config+cert reload | transport | L | ■ | W2 | with G3 |
| **G0 Linux** | deployability | **XL** | ▲ | W3 | **own track** |
| G6 protocol tail | protocol | L | ▲ | W4 | yes (P8) |

Rough critical path: **G0 dominates** (XL, parallel). W1 (~3–4 wk of additive work, parallelizable across
contributors) + W2 (~2–3 wk) can finish well before G0; W4 proceeds opportunistically with fresh context.

## Non-goals (compose an edge proxy instead)

Reverse proxy / upstreams / load balancing · ACME / auto-HTTPS · OCSP stapling (now legacy — LE dropped
OCSP Aug 2025) · proxy/edge caching · WAF. These are edge-proxy responsibilities; the intended
architecture is this app server **behind** nginx / Caddy / Envoy. Building them in would duplicate mature
tools and bloat a library whose value is a safe, fast, dependency-light origin. (All are stated non-goals
in the project docs.)

## Change log
- 2026-06-25 — Roadmap created from the server feature gap analysis (G0–G7). Sequenced into waves W1–W4;
  G0 (Linux) flagged as the parallel long-pole; decisions D1–D4 recorded. Not yet started.
- 2026-06-26 — **G2 shipped on Darwin** (W1's first phase): outbound Brotli (`Brotli.swift`, Apple's
  level-2 `COMPRESSION_BROTLI` — no C shim) + q-value `Accept-Encoding` negotiation (br > gzip, `*` /
  `identity`, `Vary: Accept-Encoding`) in `CompressionMiddleware`. 14 compression tests green incl. a
  Brotli round-trip; ASan + swift-format/SwiftLint `--strict` clean. Zstd deferred (D2); the Linux
  `libbrotlienc` shim deferred to G0.
- 2026-06-26 — **G1a shipped**: new **isolated** `HTTPObservability` module bridging the dependency-free
  seams — a swift-metrics `HTTPMetrics` sink (method×status labels only, never the path → cardinality +
  swift-prometheus CVE-2024-28867 safe) with a swift-prometheus `/metrics` exporter, a swift-log
  structured access-log middleware, and `/healthz` + drain-aware `/readyz` (a `ReadinessProbe`). Patterns
  adapted from the sibling ADServe project's `ADServeObservability`. New deps (swift-log, swift-metrics,
  swift-prometheus, +swift-atomics transitively) are confined to the module — core targets' resolved deps
  unchanged. 887 tests (+4), ASan + lint clean. Tracing + W3C trace-context (G1b) next.
- 2026-06-26 — **G1b shipped — G1 complete**: a swift-distributed-tracing `TracingMiddleware` (ported from
  ADServe) opening a `.server` span per request with the OTel HTTP attributes, marking 5xx errored, plus
  an `HTTPFieldsExtractor` that reads W3C `traceparent`/`tracestate` inbound (trace-context propagation).
  Tested against the official `InMemoryTracer`. New deps (swift-distributed-tracing, swift-service-context)
  stay confined to `HTTPObservability`. 890 tests (+3), ASan + lint clean. **Wave W1 remaining: G5, G7.**
- 2026-06-26 — **G5 shipped (responder-level)**: `FileResponder` gains precompressed `.br`/`.gz` sidecar
  negotiation (fresh + accepted + jailed; `Content-Encoding`/`Vary`/coding-ETag; identity-only for ranges,
  adapted from ADServe's `planStaticFile`), a `try_files` SPA fallback, and an opt-in HTML-escaped
  directory autoindex (off by default). No new dependency. **sendfile deferred** to a transport-layer
  phase (architectural). 896 tests (+6), ASan + lint clean. **W1 remaining: G7.**
- 2026-06-26 — **G7 shipped — Wave W1 complete**: a new **isolated `HTTPAuth`** module with
  `BasicAuthMiddleware` (RFC 7617, constant-time), a `JWT` verify core + `JWTMiddleware` (HS256/ES256/RS256
  via apple/swift-crypto, `exp`/`nbf`/`aud`/`iss`, `alg:none` + algorithm-confusion rejected), and
  `ForwardAuthMiddleware` (injected-closure escape hatch). `.wwwAuthenticate`/`.xAuthSubject` added to the
  HTTPCore registry. swift-crypto (+ `_CryptoExtras`/BoringSSL) confined to `HTTPAuth` — core targets'
  deps unchanged. 917 tests (+21), ASan + lint clean. **W1 (G2, G5, G7, G1) done; next: W2 (G3/G4 TLS),
  W3 (G0 Linux), W4 (G6 protocol tail).**
- 2026-06-26 — **G3 shipped on Darwin (W2 begins)**: mutual TLS / client certificates on the
  Network.framework backbone. `TransportTLS` gains `clientAuth` (`.none`/`.required`; `.optional` → G0)
  and a backbone-agnostic `verifyPeer` trust/pinning hook over the **DER chain** (leaf-first, portable to
  G0). `NetworkFrameworkTLS.options` now sets `peer_authentication_required` + a `verify_block` that
  extracts the chain via `sec_protocol_metadata_access_peer_certificate_chain` → `SecCertificateCopyData`
  and calls the hook (failing the handshake on `false`); the leaf subject is captured at `.ready`
  (`SecCertificateCopySubjectSummary`) and surfaced as `TransportConnection.tlsPeerSubject`. The HTTP/1 +
  HTTP/2 dispatch paths stamp it as the **server-asserted** `.xClientCertSubject` (new HTTPCore field),
  stripping any inbound spoof and rejecting a CR/LF-injecting subject via `field-value` validation
  (CWE-93). Full SAN/chain is a documented header-only limitation (richer context → G0). 925 tests (+8):
  real-loopback mTLS handshakes (subject surfaced, no-cert + pin-rejected fail, DER chain delivered
  leaf-first) through `NetworkFrameworkTransport` + `DevTLSIdentity`, plus server-level stamp/strip/inject
  tests. ASan + swift-format/SwiftLint `--strict` clean. **W2 remaining: G4 (hot responder + cert reload).**
- 2026-06-26 — **G4a shipped (hot responder/route swap)**: `HTTPServer.responder` is now a
  `Mutex<any HTTPResponder>` swapped atomically by `public reloadResponder(_:)`. Every dispatch site
  (HTTP/1, HTTP/2 buffered + concurrent, HTTP/3) reads it once via a centralized `currentResponder`
  accessor — the lock is never held across the `await` — so the graceful old/new split needs no drain: a
  request reads the table at dispatch, so in-flight requests finish on the old table and requests
  dispatched after the swap use the new one. 927 tests (+2): an `AsyncGate` holds one request in flight
  inside the old responder across the swap while a fresh request is served by the new one, then the
  parked request completes on the old — deterministic, no real-time race. ASan + lint `--strict` clean.
  **W2 remaining: G4b (hot certificate reload — restart-based).**
