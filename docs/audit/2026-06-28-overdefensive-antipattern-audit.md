# Overdefensive-code / anti-pattern / security audit — 2026-06-28

A whole-codebase audit through the combined lens of *ruthless simplicity, good taste, and fail-fast over defensive
cruft* (the "what would Carmack or Torvalds flag" brief): overdefensive code that hides bugs, dark/anti-patterns,
bad security practices, and needless convolution.

**Method.** An atomic cross-cut (global greps for forced ops / crash points / escape hatches / leftover debug, plus
CLAUDE.md-rule and file-size-budget adherence), then **8 parallel read-only scope audits** (Core · Crypto&Auth ·
HTTP/1+WS · HTTP/2+3/HPACK/QPACK · Transport socket-floor · Transport TLS/Network/QUIC · Server ·
Observability/Examples/Testing). **Every Critical/High candidate was then re-verified against the real source** before
being accepted — and that step mattered: most of the agents' "Critical" findings did not survive verification.
Vendored BoringSSL (`Sources/Core/CHTTPBoringSSL*`) was excluded as third-party.

## Headline

A **disciplined, high-quality codebase.** 264 Swift files / ~26k LOC with **zero** force-unwraps, `try!`, `as!`, or
library `fatalError`; the only `preconditionFailure`s are deliberate unsupported-backbone guards; no leftover debug
outside examples; no real TODO/FIXME debt; every file within the 400-line budget. **No true Critical was confirmed.**
The real issues are a small set of **High/Medium hardening items**, nearly all in one family: *swallowing an error or
failing open instead of failing fast* — precisely the "overdefensive code that hides a bug" the brief targets.

## Confirmed findings

| ID | Sev | Category | Location | Issue → Fix |
|----|-----|----------|----------|-------------|
| **F1** | High | Overdefensive / correctness | `Server/HTTPServer/FileResponder.swift:277-309` | `readRange`/`streamRange` swallow seek/read/open errors (`try?` → `[]` / early `return`) while `serve()` already set `Content-Length: N` → **200 with a 0-byte/short body** = response desync on keep-alive. → Fail to `500` (buffered) / throw (streamed); never under-deliver a declared length. |
| **F2** | Med-High | Overdefensive / reliability | `Transport/.../POSIXEpoll/EpollEventLoop.swift:42` · `POSIXKqueue/KqueueEventLoop.swift:32` | `epoll_create1()` / `kqueue()` return unchecked; on fd exhaustion `fd == -1` and every `epoll_ctl`/`kevent` silently no-ops → **server accepts connections but never serves them**. → Throwing `init` (both `start()`s already `throws`). |
| **F3** | High | Security / lying comment | `Server/HTTPServer/FileResponder.swift:190-198` + header doc | Jail is **lexical only** — `..`/NUL rejected, but `inRoot` uses `standardizedFileURL` (resolves `..`, not symlinks), so a symlink under root escapes despite the `traversal-safe (CWE-22)` claim. → `resolvingSymlinksInPath` before the prefix check; correct the comment. |
| **F4** | Med | Security / fail-open default | `Transport/.../Network/NetworkFrameworkTLS.swift:168` (`?? !chain.isEmpty`) · `PortableTLS/PortableTLSConnection.swift:105` (`?? true`) | On opt-in mutual TLS (`clientAuth == .required`), a nil `verifyPeer` **accepts any presented client cert**. Server-auth/one-way TLS unaffected (not a bypass), but a fail-open footgun. → Fail closed: require an explicit `verifyPeer` when `.required`. |
| **F5** | Med | Anti-pattern / PII leak | `HTTPObservability/LoggingMiddleware.swift:38` · `TracingMiddleware.swift:39` | Both log the **full request path incl. query string**; query strings carry tokens/PII and ship to log/trace backends. (Metrics correctly omit path — no cardinality blow-up.) → Log the path component only (OTel-correct); document. |
| **F8** | Low | Anti-pattern / consistency | `Server/HTTPServer/Middleware/SessionMiddleware.swift:110-117` | `base64urlDecode` lacks the URL-alphabet pre-check that `HTTPAuth/Base64URL.decode` has, so it tolerates non-canonical input (no security bypass — the HMAC still gates). → Reject non-alphabet bytes inline. |

### P3 — taste / perf / robustness (lower priority)

- **F9** — Audit the 58 `try?` sites for the same swallow-the-error pattern F1 exemplifies; propagate the ones that mask real failures.
- **F10** — Allocation trims aligned with the "minimal allocation" goal: `QueryParameters` percent-decode only when a `%` is present; `HTTPDate` format into a fixed buffer. *Only with a confirming benchmark (CLAUDE.md).*
- **F11** — `POSIXEpollConnection`/`POSIXKqueueConnection` `deinit` don't close the fd (intentional, to avoid an fd-reuse race) → an fd leaks if a connection is dropped without `close()`. Document the ownership contract prominently.
- **F12** — Example only (`httpd-example/Prefork.swift` signal handling via `signal()` not `sigaction()`; `ContentNegotiation` builds JSON/HTML by interpolation over trusted inputs). Acceptable for a sample; noted for copy-paste safety.

## Rejected false positives (verified correct — do NOT "fix")

| Agent claim | Why it's wrong |
|---|---|
| JWT algorithm-confusion / `alg:none` (Critical) | `JWT.swift:93` rejects `alg:none` **and** binds `alg == key.algorithm` via a typed `Key` enum; `requireExpiration:true`. Exemplary. |
| HMAC-SHA256 timing leak (High) | Tags are always 32 B; the length guard leaks nothing secret; the byte loop is constant-time. |
| Base64URL JWS malleability (High) | `Base64URL.decode` pre-rejects any char outside `[A-Za-z0-9-_]`. Already strict. |
| DecompressionMiddleware "inverted cap" (Critical) | `cap = min(absolute, ratio×input)` (`:50-51`) is exactly correct and overflow-safe. |
| RangeMiddleware integer overflow (Critical) | `Int(...)` returns nil on overflow → `.ignore`; in-memory body; multi-range capped at 8 (CVE-2011-3192). |
| HTTP/2 Rapid-Reset bypass (Critical) | Resets charged for active streams (`:327`) **and** engine-emitted RSTs (`:277`, MadeYouReset/CVE-2025-8671); CONTINUATION flood bounded before HPACK decode (`:163-166`). |
| HTTP/3 unbounded per-stream body (High) | `HTTP3Connection+Request.swift:190-206` bounds per-stream **and** connection-total buffered body (CWE-400/770). |
| WebSocket 64-bit length / unbounded frame (Critical) | `WebSocketFrameDecoder.swift:59` caps `payloadLength <= maxPayloadLength` before allocation; rejects the high bit (`:123`) and non-minimal lengths. |
| FieldValidation SWAR accepts 0x08 (Critical) | Traced the bit-tricks: `isControl & ~isHTAB | isDEL` rejects NUL/CR/LF/all C0/DEL. 0x08 *is* rejected. Correct + benchmarked. |
| FakeConnection "missing `throws`" compile error | A non-throwing func legally witnesses a `throws` requirement in Swift; the package builds. |
| ConnectionID wrap "~10 days" | Real figure ≈ 3 million years at 200k rps. |

## What's already excellent (don't regress)

JWT verification · the SWAR field/target validators (CWE-113 defense) · HTTP/1 CL-vs-TE smuggling defense · the HTTP/2
**and** HTTP/3 DoS suites (Rapid Reset, MadeYouReset, CONTINUATION/field-section bounds, concurrent-stream &
buffered-body caps — all CVE/RFC-cited) · decompression-bomb caps · WebSocket frame bounds · EINTR/EAGAIN/short-write
and EMFILE-backoff handling across the POSIX backbones · metrics cardinality discipline · the deliberate swift-crypto
isolation (the hand-rolled SHA/HMAC in `HTTPServer` exists so the bare server pulls no crypto graph — a sound tradeoff).

## Remediation (applied in this change set)

| ID | Status | Test coverage |
|----|--------|---------------|
| F1 | Fixed — `readRange` returns `[UInt8]?` (nil → `500`); `streamRange` throws on open failure / truncation | New `FileResponderTests.unreadableFileFailsClosed` (chmod-000 file → 500; skipped when run as root) |
| F2 | Fixed — `EpollEventLoop`/`KqueueEventLoop` `init` throws on `epoll_create1`/`kqueue` failure; both `start()` callers `try` | kqueue compiles + suite green; epoll mirrors it exactly (Linux-gated, not built on macOS) |
| F3 | Fixed — `inRoot` resolves symlinks before the containment check | `FileResponderTests.symlinkEscape` (in-root file still serves; `/link/passwd` → 403) |
| F4 | Fixed — Network backbone throws on `.required` + nil hook; PortableTLS fails closed (`?? false`, compiles under `HTTP_PORTABLE_TLS`) | New `requiredClientAuthWithoutHookIsRejected`; two existing mTLS tests updated to pass an explicit hook |
| F5 | Fixed — `LoggingMiddleware`/`TracingMiddleware` log the path only (query stripped) | New `LoggingTests.redactsQueryStringFromPath`; the tracing middleware shares the identical helper |
| F8 | Fixed — `SessionMiddleware.base64urlDecode` rejects non-URL-alphabet bytes | Existing session round-trip tests + suite green |
| F6, F7 | No change — confirmed already safe (HTTP/3 per-stream + connection body caps; WebSocket `maxPayloadLength`) | — |
| F9 | No change — all 58 `try?` sites triaged; only F1 was a harmful swallow. The rest are intentional: parse-to-optional (JWT / StructuredFields), best-effort cleanup (`close`/temp removal), fire-and-forget sends on already-doomed connections, and read-loop `receive → nil → stop` | — |
| F10 | Fixed — `QueryParameters.percentDecoded` fast-path (no `%`/`+` → return the slice, skipping two buffer allocs); `HTTPDate.imfFixdate` fills one 29-byte buffer instead of ~8 interpolation/`pad` allocations (serves the "avoid extra allocation" rule) | Existing `QueryParameters` + `HTTPDate` round-trip / known-vector tests pass |
| F11 | Documented — the deliberate no-close-in-`deinit` fd-ownership contract on `POSIXEpollConnection` / `POSIXKqueueConnection` | — |
| F12 | Reviewed — no change: `Prefork`'s `signal()` is a *deliberate, documented* choice (handle-and-`killpg` sidesteps `SA_RESTART` auto-restarting the master's `waitpid`); switching to `sigaction` would contradict that rationale. `ContentNegotiation` interpolates over trusted constants | — |

Verified: `HTTP_WARNINGS_AS_ERRORS=1 swift build` clean; the full suite passes (exit 0; ~950 tests across 13 targets), including the new/updated tests; the gated `HTTP_PORTABLE_TLS=1` build is also clean (BoringSSL graph, F4b). The Linux-gated `EpollEventLoop` (F2) was not built locally — it mirrors the locally-compiled `KqueueEventLoop` exactly and is covered by the project's existing Linux verification.

> Note: the F3 `inRoot` fix and its `symlinkEscape` test were applied in this workspace concurrently with the audit (matching the recommended fix); they are retained as-is.
