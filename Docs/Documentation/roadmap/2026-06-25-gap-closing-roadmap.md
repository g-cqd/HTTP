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
- [x] `.optional` client-auth — **shipped 2026-06-27 on the portable TLS backbone** (ADR 0004 Phase 4:
      `SSL_VERIFY_PEER` without `FAIL_IF_NO_PEER_CERT`; the full `.optional` suite is green). The *modern
      SDK-26 `NetworkListener<TLS>`* path remains blocked (investigated 2026-06-26 — kept here for the
      record): the modern `Network.TLS` builder *does* expose a three-state
      `TLS.PeerAuthentication` (`.none`/`.optional`/`.required`), and a spike confirmed `.optional` + a
      *no-cert* client handshakes cleanly (subject `nil`). But on macOS 26 / SDK 27 the modern server
      **deadlocks the handshake whenever a client presents a certificate**: `.certificateValidator` is never
      invoked and the connection never reaches `.ready`. Reproduced invariant of `.optional`/`.required`,
      TLS 1.2/1.3, legacy `NWConnection` *and* modern `NetworkConnection<TLS>` clients, direct vs.
      `NWParametersBuilder` init, and custom-validator vs. default-trust — so the modern backbone cannot
      validate a *presented* client cert (a cert-presenting client would hang the connection forever — a DoS),
      making `.optional` unshippable there. Defer it **with SNI multi-cert** to the portable BoringSSL TLS
      backbone (a real stack does request-but-don't-require *and* client-cert validation); re-evaluate the
      modern path only if a later macOS 26.x fixes the server-side `certificateValidator` client-cert path
      (file Feedback). _(Secondary spike finding, applies to any future modern-backbone work: the modern
      `NetworkConnection<TLS>` is delivered "cold" — it needs a pending `receive` to drive the handshake;
      passively awaiting `.ready` deadlocks.)_
- [x] Surface the **verified client identity** (leaf subject) as the server-asserted `.xClientCertSubject`
      header — the connection→request seam the stack already uses for `.xRequestID`/`.xAuthSubject`,
      stripping any inbound spoof. Full SAN / cert chain is a documented header-only limitation (richer
      request-scoped context → G0, same shape as G7's claims).
- [ ] `SecurityHeadersMiddleware`/docs note on pairing mTLS with auth (follow-up).
- _Gate:_ ✓ required-auth rejects no-cert + pin-rejected cert; pinning hook honored over the DER chain;
      real-loopback integration test with a `DevTLSIdentity` client surfaces its subject; server-stamp test
      strips a spoofed subject and rejects a CR/LF-injecting one (CWE-93). (`.optional` allow-both → G0.)

### [~] G4 — Graceful config & certificate reload · Effort L · Risk ■ — *Darwin shipped; SNI multi-cert → G0*
Today a cert rotation or route change needs a restart. Make both hot.
- [x] **Hot cert reload:** `ServerTransport.reload(tls:)` (default throws `.unsupported`; Network.framework
      implements it). Restart-based — the only TLS backbone fixes the server identity at listen time, and
      its challenge block is *client*-side — so it rebinds the `NWListener` on the same port with the new
      identity. `NWListener` cannot share a port (SO_REUSEADDR is not enough), so the old listener is
      retired (its `.cancelled` awaited to free the port) before the replacement binds: a brief
      *new*-connection accept gap, but already-accepted `NWConnection`s are independent of the listener and
      keep serving on their original identity (zero existing-connection drops). `HTTPServer.reloadCertificate`
      forwards to it.
- [x] **Hot responder/route swap:** `HTTPServer.responder` is a `Mutex<any HTTPResponder>` swapped by
      `reloadResponder(_:)`; every dispatch reads it once (never across the `await`), so a request in
      flight finishes on the table it read and new requests use the new one — no drain needed.
- [x] **SNI multi-cert selection** (sub-gap from the matrix): pick the identity by SNI server-name at
      handshake — **shipped 2026-06-27 on the portable TLS backbone** (ADR 0004 Phase 5;
      `SSL_CTX_set_tlsext_servername_callback` + per-name `SSL_CTX`). Network.framework still lacks the
      server-side callback, so this is portable-backbone-only. `.optional` client-auth shipped with it
      (Phase 4).
- _Gate:_ ✓ in-process reload-under-load gate (real loopback): after `reload(B)` a new connection's client
      verify-block sees cert B's subject while an existing cert-A connection still round-trips (zero
      existing-connection drops); the responder swap keeps in-flight requests on the old table. The external
      bench "reload-mid-run" case is a noted follow-up; SNI picks the right cert → G0.

---

## W3 — Linux deployability (the big one)

### [ ] G0 — Linux support · Effort XL · Risk ▲ — *start now, parallel track*
The single biggest gap: servers run on Linux; we're Apple-only. The sans-I/O engines are already pure and
portable — the lift is the I/O floor and a non-Network.framework TLS path. **Decision required first — see
[Decisions needed](#decisions-needed) D1 (TLS backend).**
- [ ] **`POSIXEpoll` transport backbone** (`Sources/Transport/HTTPTransport/POSIXEpoll/`): epoll readiness
      loop modeled on the existing `KqueueEventLoop`; `SO_REUSEPORT` prefork (already proven on kqueue);
      EINTR/EAGAIN parity; dual-stack IPv6.
- [x] **Portable TLS path** (D1) — **shipped 2026-06-27 (macOS arm64)**, see
      **[ADR 0004](../adr/0004-portable-tls-backbone.md)** (Phases 1–6). A TLS backbone that is *not*
      Network.framework: `PortableTLS{Transport,Connection}` over the existing `POSIXSocket` accept loop +
      ALPN / TLS-1.3-floor / strict-ALPN policy; mTLS (G3), `.optional`, SNI multi-cert, and hot reload
      (G4) all work — the features Network.framework cannot do. **Now on vendored, symbol-prefixed
      BoringSSL (Phase 6, commit `79e821d`)** — self-contained, no system OpenSSL, no `HTTP_OPENSSL_PREFIX`;
      `scripts/vendor-boringssl.sh` regenerates the tree. Remaining for Linux: the `POSIXEpoll` backbone
      (below) + the multi-arch symbol-mangling/CI (ADR 0004 §6.5, needs a Linux runner).
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

### [~] G6 — Finish the modern-protocol tail · Effort L · Risk ▲ — *protocol features done; only Conformance CI (P10) remains*
Engines exist; the conformance-sensitive integration remains. Tracked in the completion roadmap; surfaced
here for completeness.
- [x] **Native HTTP/2 streaming server adoption** (completion P6b/S4): adopted — `HTTPServer+HTTP2Streaming`
      drives the engine's incremental DATA API; the late-`WINDOW_UPDATE` `ControllableConnection` harness +
      `HTTP2StreamingServerTests` prove the producer/serve-loop rendezvous deadlock-free.
- [x] **QPACK dynamic-table integration** (completion P8/S5): bidirectional dynamic table + blocked streams
      (the encoder inserts on the QPACK encoder stream and references the dynamic table; the decoder buffers
      a blocked section until its Required Insert Count is satisfied).
- [x] **WebSocket over HTTP/3** (RFC 9220): Extended CONNECT over h3 — `HTTP3Connection` surfaces the tunnel
      (`extendedConnect`/`tunnelData`/`tunnelClosed`) and accepts it (`acceptTunnel`/`sendTunnelData`/
      `closeTunnel`); `HTTPServer+HTTP3` advertises ENABLE_CONNECT_PROTOCOL when a WebSocket handler is set
      and drives the tunnel (CSWSH origin defense + permessage-deflate, mirroring the RFC 8441 h2 path).
- [x] **HTTP/2 priority scheduling** (RFC 9218) — done (completion P8/S1).
- [ ] **Conformance CI** (completion P10): Autobahn (WS) Docker job, h3spec/QUIC interop, h3 load-client
      wired into the bench matrix. **Remaining** — infra (not locally verifiable); the only open G6 item.
- _Gate (per item):_ QPACK/h3 conformance + fuzz green; native-h2-streaming deadlock test on the harness;
      WebSocket-over-h3 handshake + echo over a real-QUIC loopback; Autobahn green or explicit logged skip;
      h2spec/h3spec still green.

---

## Decisions needed

These are forks the team should resolve before the dependent phase starts:

- **D1 — Linux/portable TLS backend (blocks G0 W3-b + W2's deferred `.optional`/SNI).** **Resolved →
  see [ADR 0004](../adr/0004-portable-tls-backbone.md) (Proposed, awaiting ratification).** Investigation
  killed option (c): swift-crypto's BoringSSL is **libcrypto-only** (no `ssl/`, no `SSL_CTX_*`), so "a
  minimal TLS-record binding" is really "hand-write a TLS 1.3 stack" (XXL, a standing security
  liability). The decision: a **provider-seam** architecture (`TLSProvider`) with the libssl calls
  behind one C shim, **system OpenSSL first** (gated opt-in via `HTTP_PORTABLE_TLS`; the default build
  stays apple-only), and **vendored BoringSSL (option a) as the drop-in productionization** behind the
  same seam. Ratification point: system-OpenSSL-first vs. vendor-up-front — the seam makes it low-regret.
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
- 2026-06-26 — **G4b shipped — W2 complete (G3 + G4 done on Darwin)**: hot TLS certificate reload.
  `ServerTransport` gains `reload(tls:)` (default throws the new `TransportError.unsupported`;
  Network.framework implements it), and `HTTPServer.reloadCertificate(_:)` forwards to it. Restart-based:
  `NetworkFrameworkTransport` stores the stream continuation + the swappable identity in `State` and
  `makeParameters(tls:)` takes the identity (no longer the immutable `configuration.tls`); on reload it
  builds a fresh `NWListener` with the new identity, retires the old one — awaiting its `.cancelled` so the
  port frees, since `NWListener` can't share a port (SO_REUSEADDR ≠ SO_REUSEPORT, which it doesn't expose) —
  then binds the replacement on the same port and feeds the same stream. A brief *new*-connection accept
  gap, but already-accepted `NWConnection`s are independent and keep serving (zero existing-connection
  drops). 930 tests (+3): real-loopback reload-under-load gate — after `reload(B)` a new connection's client
  verify-block sees cert B's subject while the existing cert-A connection still round-trips; reload throws
  `.unsupported` on a non-Network backbone; `reloadCertificate` delegates. SNI multi-cert + `.optional`
  client-auth deferred to G0 (need a server-side SNI callback Network.framework lacks). ASan +
  swift-format/SwiftLint `--strict` clean. **W2 done; next: W3 (G0 Linux), W4 (G6 protocol tail).**
- 2026-06-26 — **W4 / G6: WebSocket over HTTP/3 shipped (RFC 9220)** — the one unbuilt G6 protocol feature
  (investigation found the gap-closing G6 markers stale: native h2 streaming S4 and the bidirectional QPACK
  dynamic table S5 were already done, now reconciled to `[x]`). Extended CONNECT over h3, mirroring the
  proven RFC 8441 (h2) path. Engine: `HTTP3Connection.Event` gains `extendedConnect`/`tunnelData`/
  `tunnelClosed`; the request path uses the mapper's `:protocol` (a shared `recordDecodedRequest` marks the
  stream a tunnel, rejecting it H3_MESSAGE_ERROR without ENABLE_CONNECT_PROTOCOL) and a new
  `surfaceStream`/`surfaceTunnel` emits the tunnel events as soon as the CONNECT HEADERS decode (no FIN
  wait); new `HTTP3Connection+Connect.swift` adds `acceptTunnel` (static 200, stream kept tracked) /
  `sendTunnelData` (DATA frame) / `closeTunnel`. Server: `HTTPServer+HTTP3` advertises
  ENABLE_CONNECT_PROTOCOL when a WebSocket handler is set and drives the tunnel over the QUIC stream — same
  CSWSH origin defense + permessage-deflate negotiation as the h2 tunnel. The SETTINGS + request-mapper
  groundwork already existed. 936 tests (+6): engine extended-CONNECT/tunnel-data/close + reject-when-
  disabled, plus a real-QUIC loopback WebSocket-over-h3 handshake + echo; full h3spec + h2spec conformance
  green; ASan + swift-format/SwiftLint `--strict` clean. **G6 remaining: Conformance CI (P10) — infra, not
  locally verifiable. Other waves: W3 (G0 Linux).**
- 2026-06-26 — **W2 deferred `.optional` via the modern SDK-26 backbone: investigated, blocked, reverted —
  stays → G0/BoringSSL.** Attempted to ship `.optional` client-auth on a new modern `NetworkListener<TLS>`
  backbone (gated `@available(macOS 26, iOS 26, *)`, mirroring `ModernQUICTransport`). The full implementation
  was written and compiled clean (warnings-as-errors), but a runtime spike against macOS 26 / SDK 27 found a
  platform blocker: the modern Network TLS **server deadlocks the handshake whenever a client presents a
  certificate** — `Network.TLS.certificateValidator` is never invoked and the connection never reaches
  `.ready`. Invariant across `.optional`/`.required`, TLS 1.2/1.3, legacy `NWConnection` *and* modern
  `NetworkConnection<TLS>` clients, direct vs. `NWParametersBuilder` init, and custom-validator vs.
  default-trust. `.optional` + a *no-cert* client works (handshake completes, subject `nil`), but a
  cert-presenting client would hang the connection forever (a DoS) — so the backbone is unshippable for
  client-auth. Changes reverted to baseline (936 tests, unchanged); `.optional` (and SNI multi-cert) remain
  deferred to the portable BoringSSL TLS backbone (G0), where a real stack does request-but-don't-require
  *and* client-cert validation. Re-evaluate the modern path only if a later macOS 26.x fixes the server-side
  `certificateValidator` client-cert path (Feedback to file). Secondary spike note for any future
  modern-backbone work: the modern `NetworkConnection<TLS>` is delivered "cold" and needs a pending `receive`
  to drive its handshake — passively awaiting `.ready` deadlocks.
- 2026-06-27 — **D1 resolved: portable TLS backbone designed → [ADR 0004](../adr/0004-portable-tls-backbone.md)
  (Proposed).** Design/ADR-first (no backbone code yet). Investigation settled the fork: swift-crypto's
  `CCryptoBoringSSL` is **libcrypto-only** (tree has `crypto/`/`gen/`/`third_party/`, no `ssl/`; no
  `SSL_CTX_*`), so roadmap option (c) collapses to hand-writing a TLS 1.3 stack (XXL/security liability) and
  is rejected; `swift-nio-ssl` stays off the table (CLAUDE.md). Decision: a **provider-seam** (`TLSProvider`)
  with the only `libssl` interop behind one C shim (`CHTTPBoringSSL`), the accept loop reusing the existing
  `POSIXSocket` layer, and the backbone (`PortableTLS{Transport,Connection}`) provider-agnostic — **system
  OpenSSL first** (gated opt-in `HTTP_PORTABLE_TLS`; default build stays apple-only), **vendored BoringSSL
  (option a) the drop-in follow-up** behind the same seam. The ADR maps every requirement to the
  OpenSSL/BoringSSL API and shows the two W2-blocked features fall out natively: `.optional` =
  `SSL_VERIFY_PEER` without `FAIL_IF_NO_PEER_CERT`; SNI multi-cert = `SSL_CTX_set_tlsext_servername_callback`
  + per-name `SSL_CTX`. Six-phase rollout (plumbing+handshake spike → provider → transport → mTLS tri-state →
  SNI/reload → vendored BoringSSL), each gated, with `openssl s_client`/`curl` interop as the portability
  proof. **Awaiting ratification:** system-OpenSSL-first vs. vendor-up-front (the seam makes it low-regret).
- 2026-06-27 — **ADR 0004 ratified (system-OpenSSL-first); portable TLS Phase 1 (plumbing) shipped.** New
  `CHTTPBoringSSL` C shim — the single `#include <openssl/...>` surface — wrapping the macro-based OpenSSL
  config APIs the Swift importer can't call (version pinning, PKCS#12 → `SSL_CTX`, ALPN select/offer, a
  memory-BIO handshake pump), plus a one-time legacy-provider load so OpenSSL 3 parses DevTLSIdentity's
  `-legacy` PKCS#12. `Package.swift` adds the shim + OpenSSL header/link flags **only under
  `HTTP_PORTABLE_TLS`** (default graph stays apple/swiftlang-only; verified the shim is absent without the
  flag), passing `-Xcc -I<prefix>` to consumers so the clang importer finds the headers; OpenSSL prefix via
  `HTTP_OPENSSL_PREFIX` (Homebrew `openssl@3` default). New gated test (`#if canImport(CHTTPBoringSSL)`)
  proves the plumbing end-to-end: the shim links + imports, and a real **TLS 1.3 handshake negotiates ALPN
  `h2`** over memory BIOs using a DevTLSIdentity identity (no keychain). Default build-tests green; gate green
  under the flag; swift-format + SwiftLint `--strict` clean. **Next: Phase 2** — `TLSProvider` +
  `OpenSSLProvider` + `PortableTLSConnection` (identity, memory-BIO byte bridge, receive/send/close).
- 2026-06-27 — **portable TLS Phase 2 (connection) shipped.** `OpenSSLTLS` (the `SSL_CTX` builder + ALPN
  metadata, mirroring `NetworkFrameworkTLS`) + `PortableTLSConnection` (a `TransportConnection` carrying a
  libssl session over an accepted socket: `performHandshake`/`receive`/`send`/`close`). Two deliberate
  deviations from ADR 0004's sketch, both recorded there: **(a)** no `TLSProvider` protocol — OpenSSL and
  BoringSSL share one C API through one shim, so a protocol would have a single conformer forever (YAGNI);
  the shim's backing lib is the seam and the Swift types mirror the Network backbone. **(b)** v1 drives
  **blocking `SSL_set_fd` on a per-connection serial `DispatchQueue`** bridged to `async` (the
  ADR-sanctioned first step), with the non-blocking memory-BIO + shared-readiness path as the perf
  follow-up. New gated test round-trips `ping` end-to-end through TLS over a `socketpair` (server =
  `PortableTLSConnection`, client = raw libssl). Default build-tests green; gate green under the flag;
  swift-format + SwiftLint `--strict` clean. **Next: Phase 3** — `PortableTLSTransport` (accept loop over
  `POSIXSocket` → `AsyncStream`, `boundPort`, `shutdown`); gate: the one-way-TLS + ALPN suite + `curl`
  interop.
- 2026-06-27 — **portable TLS Phase 3 (transport) shipped — `curl` interops over the new backbone.**
  `PortableTLSTransport` is a full `ServerTransport`: it binds via the shared `POSIXSocket` accept
  plumbing (the same the swift-system/kqueue backbones use), accepts on a dedicated blocking-`accept()`
  thread, wraps each fd in a libssl session (`SSL_new`/`SSL_set_fd`), drives the handshake off the
  accept thread, and surfaces the connection only at `.ready` (a failed/ALPACA-refused handshake is
  never yielded). The shared `SSL_CTX` is carried to the accept loop in an `@unchecked Sendable` box
  (a raw `OpaquePointer` in a `Mutex<State>` trips `RegionIsolation`) and freed when the loop exits.
  Wired into the abstraction: a new `TransportBackbone.portableTLS` case + `TransportFactory` routing
  (gated; selecting it without `HTTP_PORTABLE_TLS` `preconditionFailure`s with a clear message;
  `TransportTests` excludes it from the cleartext factory battery, like `.fake`). Added a tiny
  `CHTTPBoringSSL_connect_loopback` C helper so a libssl client can drive the loop without `sockaddr`
  plumbing in Swift. **Gate met:** a libssl client negotiates ALPN `h2` and round-trips bytes through
  the transport, **and `curl` interops over TLS** (a real non-Network.framework client — the
  portability proof) exchanging HTTP/1.1 and negotiating `http/1.1` ALPN. Full **936-test** default
  suite green (the ungated abstraction changes don't regress it); gates green under the flag;
  `project-hooks` (swift-format + SwiftLint) clean. **Next: Phase 4** — mTLS tri-state
  (`.none`/`.optional`/`.required` + `verifyPeer`/DER + `tlsPeerSubject`), where the W2-blocked
  `.optional` finally works (`SSL_VERIFY_PEER` without `FAIL_IF_NO_PEER_CERT`).
- 2026-06-27 — **portable TLS Phase 4 (mTLS tri-state) shipped — `.optional` finally works.** The W2
  payoff: `.optional` client-auth runs natively on the portable backbone, the exact feature the macOS 26
  modern Network path deadlocked on. `OpenSSLTLS` maps client-auth to `SSL_VERIFY_NONE` /
  `SSL_VERIFY_PEER` / `+ SSL_VERIFY_FAIL_IF_NO_PEER_CERT` with a **permissive TLS-layer verify**
  (replacing default trust, so self-signed / private-CA client certs are admissible — the G3 "the verify
  hook is the policy" posture); the real decision — `verifyPeer` over the **leaf-first DER chain** (new
  shim `peer_der_chain`, leaf emitted explicitly since server-side libssl separates it) + presence rules
  — is applied **post-handshake** by the connection, which also captures `tlsPeerSubject` (leaf CN via
  `peer_subject`). `TransportTLS.ClientAuth.optional` is re-added (reverted earlier with the dead
  modern-Network path); `NetworkFrameworkTLS.options` now **rejects `.optional` with `.unsupported`**
  (fail-closed, no silent degrade to one-way TLS — Network can't request-but-don't-require). **Gate met:**
  the full mutual-TLS suite — the `.required` battery mirrored from `NetworkFrameworkMutualTLSTests`, plus
  the **three `.optional` cases the Network backbone couldn't satisfy** (admits a no-cert client with
  `tlsPeerSubject == nil`; surfaces a presented subject; pins a `verifyPeer`-rejected cert). Full
  **936-test** default suite green (the ungated `.optional`/Network-reject changes don't regress
  `.required` mTLS); 12 gated portable-TLS tests green under the flag; `project-hooks` clean. **Remaining:
  Phase 5** (SNI multi-cert — the other W2/G4 deferral) **and Phase 6** (vendored BoringSSL, to retire the
  system-OpenSSL dependency).
- 2026-06-27 — **portable TLS Phase 5 (SNI multi-cert) shipped — the other W2/G4 deferral done.**
  Per-server-name certificate selection (RFC 6066 §3), the hook Network.framework has never exposed
  (legacy *or* modern). `TransportTLS` grows an additive `sniIdentities` name→identity map (single-
  identity callers unaffected); `OpenSSLTLS` builds one `SSL_CTX` per name (factored out a `makeContext`
  helper) and installs `SSL_CTX_set_tlsext_servername_callback` over a per-default-context registry —
  in the shim (`enable_sni` / `add_sni_context`, attached via `ex_data`, the registry + its up-ref'd
  contexts freed when the default ctx is freed) — that swaps to the matching context, falling back to
  the default for an unmatched / absent name. New shim `set_sni` (client `SSL_set_tlsext_host_name`) for
  the test. **Gate met:** a libssl client's `server_name` selects the matching leaf for two names, and
  the default `localhost` leaf for an unmatched name and for no-SNI. Full **936-test** default suite
  green (the ungated `sniIdentities` addition is additive); **13** gated portable-TLS tests green under
  the flag; `project-hooks` clean. **Remaining: hot reload** (G4b parity on this backbone — a
  `Mutex`-guarded `SSL_CTX` swap, no port rebind) **and Phase 6** (vendored BoringSSL, to retire the
  system-OpenSSL dependency and make the default-off backbone self-contained).
- 2026-06-27 — **portable TLS hot reload (G4b parity) shipped — the G4 deferral set is now complete.**
  `PortableTLSTransport.reload(tls:)` overrides the `ServerTransport` default (which throws
  `.unsupported`): it builds a new `SSL_CTX` and atomically swaps it into the `Mutex<State>`, so new
  handshakes use the new identity while connections already accepted keep serving on the context they
  handshook with (libssl refcounts it). **No port rebind** — the listening socket is untouched, so
  there is no accept gap (simpler than the Network backbone's retire-and-rebind reload). The `SSL_CTX`
  moved from an accept-loop-captured box into shared state; `surface` now snapshots it under the lock
  and `SSL_CTX_up_ref`s across `SSL_new` so a concurrent reload's free can't race it (the new `SSL`
  then holds its own ref). A bad identity throws before the running context is touched; reload before
  `start()` (or after shutdown) fails closed with `.closed`. **Gate met:** a libssl client is served
  cert A, then cert B after `reload(B)`, on the same port; reload-before-start throws. Full **936-test**
  default suite green (reload is gated-only — no ungated change); **15** gated portable-TLS tests green
  under the flag; `project-hooks` clean. **The portable TLS backbone is now feature-complete for v1**
  (one-way TLS + ALPN, mTLS `.none`/`.optional`/`.required` + `verifyPeer`, SNI multi-cert, hot reload,
  `curl` interop). **Only remaining: Phase 6** — vendor BoringSSL behind the same shim to retire the
  system-OpenSSL link and make the default-off backbone self-contained + reproducible (XL).
