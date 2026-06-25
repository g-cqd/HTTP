# Deep Hardening Audit & Remediation — 2026-06-25

A second-pass adversarial security audit + remediation, going **deeper than the 2026-06-22 audit**:
every prior "fixed" claim was re-derived from the current source, each candidate finding was challenged
2–3× (false positives discarded), and the newest surfaces (HTTP/3, QPACK, middleware, cookies, the
reworked abuse budget, the resumable chunked decoder) were treated as unaudited. Findings carry a
`file:line` + an RFC §/CVE/CWE; every fix ships with mutation-resistant regression tests
(`Tests/MUTATION-OPERATORS.md`) and passes the full suite + SwiftLint + swift-format.

Threat model: all bytes from the network are hostile until validated; the engines fail **closed** (typed
error → the correct protocol response). Posture decision (owner): **secure-by-default without throttling
legitimate throughput**; **breaking changes acceptable** (pre-1.0).

---

## 1. Methodology

Adversarial fan-out across every surface (h1, h2, HPACK, h3, QPACK, WebSocket, transport/TLS, HTTPCore,
server/middleware), each cross-referenced against the local RFC/CVE/BCP corpus, **plus independent
re-verification of every load-bearing claim by reading the code** (the sub-agents' "all clear" on the
newest code was not trusted). Each finding was then challenged 2–3× with a concrete attack and only kept
if it survived.

Two findings were **downgraded on re-examination** (the discipline working as intended):
- **F-H3SET** (`HTTP3Settings` `Int(clamping:)`): RFC 9114 §7.2.4 sets **no upper bound** on the
  QPACK/field-section settings, so clamping is spec-acceptable and never sizes a v1 allocation (the QPACK
  dynamic table is pinned off). Rejecting would have introduced a spec bug. Documented, not "fixed."
- **QPACK "unbounded encoded size"** (sub-agent V1): a **false positive** — the h3 frame length is bounded
  to `maxHeaderListSize` and the decoder enforces `maxFieldCount`/`maxFieldSize`.

---

## 2. Findings register

Severity = exploitability × blast-radius. `★` = new (missed by the 2026-06-22 audit *and* the fan-out
sub-agents).

### Critical
| ID | Finding | Evidence | Standard |
|---|---|---|---|
| ★F-LIMITS | **Insecure-by-default ceilings** — `maxConnections` / `maxConnectionsPerClient` defaulted to `1_048_576`, defanging the global (T-F2) and per-client (T-F4) caps; the Rapid-Reset apparatus existed but was unreachable. | `HTTPLimits.swift` init | CWE-770 |
| ★F-CHUNKBUF | **Unbounded chunked body-phase buffer** — the inbound-buffer cap applied only pre-headers; an endless chunk-size/ext/trailer line with no CRLF never reached `beginChunk`, so neither the ext- nor body-bound fired → single-connection OOM. | `HTTPServer.readRequest` + `ChunkedBodyDecoder.readLine` | RFC 9112 §7.1; CWE-400/770 |

### High
| ID | Finding | Evidence | Standard |
|---|---|---|---|
| F-REFUSED | **REFUSED_STREAM uncharged** — the concurrency-cap path emitted RST_STREAM after a full HPACK decode but never charged the abuse budget → flood new HEADERS for unbounded RST + decode work (Rapid-Reset/MadeYouReset bypass). | `HTTP2Connection.completeHeaderBlock` | CVE-2025-8671 / CVE-2023-44487 |
| ★F-FRAMEFLOOD | **Cheap/empty-frame floods unbudgeted** — zero-length non-final DATA, PRIORITY, WINDOW_UPDATE-on-closed, and SETTINGS-ACK charged nothing. | `+FlowControl` / `+ControlFrames` | CVE-2019-9513 / -9518 |
| F-CSWSH | **WebSocket Origin defaulted open** — `isOriginAllowed`/`ClosureWebSocketHandler` admitted every origin; an unconfigured server was wide open to cross-site WebSocket hijacking. | `WebSocketHandler` / `ClosureWebSocketHandler` | RFC 6455 §10.2; CWE-346/1385 |

### Medium
| ID | Finding | Evidence | Standard |
|---|---|---|---|
| ★F-COOKIE | **Cookie attribute injection** — `SetCookie.isValid` validated only name+value; `Domain`/`Path` were interpolated raw → attribute injection / header splitting via the public `headerValue`. | `Cookie.swift` | RFC 6265bis §4.1; CWE-113 |
| F-CORS | **`.any` + credentials reflected any origin** with `Access-Control-Allow-Credentials: true`; reflected origins carried no `Vary: Origin`. | `CORSMiddleware.swift` | Fetch §3.2; CWE-942 |
| F-WSUTF8 | **Non-incremental UTF-8** — text validated only after the whole (up to `maxMessageSize`) message buffered. | `WebSocketConnection` | RFC 6455 §8.1 |
| F-BUDGETKNOB | Reset & control-frame budgets **shared one knob**. | `+AbuseBudget` | DoS tuning |

### Deferred (task #10 — transport reliability; the primary Network.framework backbone is unaffected)
`F-EMFILE` — the accept-error `usleep` sits on the shared kqueue/dispatch event-loop queue; a correct
fix needs a timer-based re-arm (those synchronous accept loops can't `await`), so the bounded ~10 ms
back-off stays as an acceptable interim. (`F-IPV4` dual-stack and `T-F14` listen backlog were resolved
by the transport dual-stack/backlog work; `F-ALPN` is resolved in §3.)

---

## 3. Fixes implemented (branch `harden/deep-audit-prism-wt`)

| Finding(s) | Fix | Tests |
|---|---|---|
| F-LIMITS | `maxConnections` 65 536, `maxConnectionsPerClient` 1 024 (was 1 048 576); `maxConcurrentStreams` stays bounded 128; add `.highThroughput` (trusted) + `.hardened` presets. | `HTTPLimitsTests` defaults + preset coverage |
| F-CHUNKBUF | `ChunkedBodyDecoder.readLine` bounds the in-progress size/ext/trailer line by `maxFieldSize` → fail closed. | unterminated size + trailer-line DoS regressions |
| F-REFUSED, F-FRAMEFLOOD, F-BUDGETKNOB | Charge the budget on the REFUSED_STREAM path; charge zero-len DATA / PRIORITY / WINDOW_UPDATE-on-closed / SETTINGS-ACK; add a separate `maxControlFramesPerInterval`. | REFUSED-flood, PRIORITY-flood, empty-DATA-flood, budget-independence |
| F-COOKIE | Validate `Domain`/`Path` octets + `__Host-`/`__Secure-` prefix invariants; `headerValue` → `String?` (fail-closed). | attribute-injection + prefix + nil-headerValue |
| F-CORS | `.any` is credential-free; add `.allowList`; emit `Vary: Origin` on reflected origins. | wildcard-never-credentialed, allow-list reflect+Vary, deny |
| F-CSWSH | Default Origin policy is now `origin == nil` (admit non-browser, reject browser origins until allowlisted). | default-policy reject-browser / admit-no-Origin |
| F-WSUTF8 | `IncrementalUTF8Validator` (RFC 3629 DFA) validates each text fragment as it arrives; one-shot Close-reason check delegates to it. | scalar-split-across-fragments, fail-fast, partial-scalar-at-end |
| F-ALPN | Over TLS, refuse a connection that negotiated neither `h2` nor `http/1.1` (incl. no ALPN) instead of silently serving h1; `TransportConnection.isSecure` distinguishes TLS from cleartext (RFC 7301 §3.2). | secure+http1.1 served / secure+nil refused / secure+unserved refused / cleartext+nil served |

**Coherency / idiom (same branch):** unified the ~99%-identical `HTTP2RequestMapper`/`HTTP3RequestMapper`
into a generic `HTTPCore.RequestMapper` (single validation source); built the M4 **routing result-builder
DSL** (`Router`/`Route`/`RouteBuilder`, `:param` capture, 404/405); added `ServerResponse.text/.json/.status`;
added the `HTTPMetrics` observability seam + `MetricsMiddleware` (dependency-free, bridgeable to swift-metrics).

---

## 4. Verified already-sound (negative space — do not regress)

`ByteReader` (`~Escapable`/`RawSpan`, bounds-checked, lifetimes) · `QUICVarint` (62-bit, no overflow) ·
**QPACK** count-bomb defended · `HTTPDate` (GMT/POSIX civil-from-days) · h2 flow-control overflow/underflow
+ `WINDOW_UPDATE=0` · request-smuggling core (CL/TE/chunked precedence) · WebSocket framing/masking
(SIMD16 unmask) · SIGPIPE on all POSIX backbones · kqueue continuation drain · TLS 1.3 pin · the
per-*connection* idle watchdog · `HTTPMethod` token validation · Huffman nibble-DFA.

---

## 5. Breaking changes (need CHANGELOG + `Security.md` entries)

- `HTTPLimits.default` connection ceilings lowered — restore via `.highThroughput`.
- `SetCookie.headerValue` is now `String?`.
- `CORSMiddleware(.any, allowCredentials: true)` no longer reflects credentials — use `.allowList`.
- `WebSocketHandler.isOriginAllowed` default now denies browser origins — allowlist to admit.

---

## 6. Verification

Per fix: a failing test first (the concrete attack), then green; boundary + concrete-typed-error
assertions; mutation spot-checks. Suite gates: full `swift test` (11 bundles, all green), `swift format
lint --strict`, SwiftLint `--strict` (pre-commit), `swift build` with `HTTP_WARNINGS_AS_ERRORS=1`.

## 7. Remaining roadmap

Phase 3 CI allocation-ceiling gates · Phase 4 perf (inbound-buffer cursor, HPACK ring table,
`reserveCapacity`, `InlineArray`/`OutputSpan`) · Phase 7 (`Expect: 100-continue`, inbound decompression
wired to the reserved bounds, Structured Fields → priorities) · observability seam · the transport
follow-up · reconcile `Security.md` + ADR for the secure-default posture.

*Compiled from an adversarial fan-out plus independent code-level re-verification of every load-bearing
claim; the secure-default posture and the breaking-change set were confirmed with the owner.*
