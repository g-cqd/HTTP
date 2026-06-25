# HTTP Server — Completion Roadmap (progress tracker)

Durable, in-repo progress tracker for the feature-completion campaign. Sequential, on `main`, no
worktrees. Each phase lands behind the project gates (build + full tests + ASan/fuzz on touched paths +
swift-format/SwiftLint `--strict`, signed commit). Tick a box only when its gate is green and committed.

Plan of record: `~/.claude/plans/wise-discovering-minsky.md`. Baseline: `main@cab7c72`, 734 tests green.

## Legend
- [ ] not started  ·  [~] in progress  ·  [x] done (gate green + committed)

## Phases

- [x] **P0 — Tracking scaffold.** This doc + the live task list; battletest worktree removed (fully
      merged into main; branch ref `campaign/battletest` kept).

- [x] **P1 — Router DX & request ergonomics.** Route groups + per-group middleware, wildcard/catch-all,
      OPTIONS auto-handling + `Allow` (on `OPTIONS` and `405`), `.options`/`.head` factories, typed
      query/cookie accessors. _Gate:_ RouterTests for each; example builds + serves. ✓ 752 tests green.

- [x] **P2 — Conditional + Range completeness.** `If-Match`/`If-Unmodified-Since` (→412),
      `If-Modified-Since` (→304), `If-Range`, `Last-Modified`, §13.2.2 precedence; multi-range
      `206 multipart/byteranges`. _Gate:_ precedence + multi-range tests; no 304/206/416 regression.
      ✓ 767 tests green; `HTTPDate.parse` added (Foundation-free, 25× faster than `DateFormatter`).

- [x] **P3 — Operational middleware.** RateLimit (RFC 6585, 429 + Retry-After over `RollingWindow`,
      bounded store), RequestID (X-Request-ID propagate/mint, unsafe-id stripped), Session (HMAC-SHA256
      signed cookie via CryptoKit, tamper-rejecting). _Gate:_ limit-trip + request-id + session
      sign/verify/tamper tests. ✓ 777 tests green; ASan clean.

- [ ] **P4 — Inbound decompression breadth.** `deflate` (raw zlib) + `brotli` (`COMPRESSION_BROTLI`),
      gzip `FLG≠0`, optional CRC/ISIZE; same bomb caps (CWE-409). _Gate:_ per-codec round-trip + bomb
      fuzz never-traps; ASan clean.

- [ ] **P5 — RFC 9111 response caching.** CacheMiddleware + bounded LRU `ResponseCache`: Cache-Control,
      freshness (§4.2), `Age` (§5.1), Vary key, revalidation. _Gate:_ freshness/Vary/eviction tests; no
      caching of uncacheable responses.

- [ ] **P6 — Streaming bodies (keystone).** Additive, source-compatible `ResponseBody`
      {bytes/stream/file}; h1 chunked send-loop, h2 fed from async source, h3 multi-DATA; middleware
      pass-through guards. _Gate:_ full suite green (buffered path byte-identical), SSE/chunked test per
      engine, alloc pins unchanged, ASan clean.

- [ ] **P7 — Static file serving.** FileResponder: traversal-safe (CWE-22), MIME, Last-Modified/ETag
      from mtime+size, Range + conditional (reuse P2), `.file` body. _Gate:_ traversal rejected,
      validators correct, ranged/conditional/streamed-download tests.

- [ ] **P8 — Protocol depth.** QPACK dynamic table (RFC 9204, encoder/decoder streams, eviction,
      blocked bound; static-only fallback), priority scheduling (RFC 9218), WebSocket permessage-deflate
      (RFC 7692, bomb-capped). _Gate:_ QPACK/h3 conformance + fuzz, priority-order test, pmd round-trip;
      h2spec still green.

- [ ] **P9 — Observability bridges.** New `Sources/Observability/` module(s): swift-log access/structured
      sink + swift-distributed-tracing span-per-request over `HTTPMetrics`. Deps isolated to the bridge.
      _Gate:_ bridge tests; core targets' dep list unchanged.

- [ ] **P10 — Conformance & tooling.** Autobahn (WS) CI job (Docker-gated), h3spec/QUIC interop, h3
      load-client for the bench matrix; flip low-noise benchmark baseline gates. _Gate:_ CI green or
      explicit logged skips (no silent omission).

- [ ] **P11 — Performance backlog (Iron-Law gated).** HPACK O(n)→hashed lookup; h3 receive-side borrow;
      NF zero-copy receive; h3 0-RTT if Apple exposes a QUIC server early-data API. _Gate per item:_
      before/after measurement, zero conformance/fuzz regression, ASan clean.

## Change log
- 2026-06-25 — P0 scaffold created; battletest worktree removed; roadmap approved.
- 2026-06-25 — P1 done: route groups + per-group middleware, catch-all, auto-OPTIONS/Allow (+405 Allow),
  `.options`/`.head` factories, typed `query`/`cookies` accessors + `@dynamicMemberLookup`. 752 tests.
- 2026-06-25 — P2 done: full §13.2.2 conditional precedence (If-Match/If-Unmodified-Since→412,
  If-Modified-Since→304, If-Range), `Last-Modified`; multi-range `multipart/byteranges` (CVE-2011-3192
  cap); new `HTTPDate.parse` + shared `EntityTag`. 767 tests; ASan clean.
- 2026-06-25 — P3 done: RateLimitMiddleware (429 + Retry-After, bounded `RollingWindow` store),
  RequestIDMiddleware (mint/propagate, unsafe-id stripped), SessionMiddleware (HMAC-SHA256 signed
  cookie via CryptoKit, tamper-rejecting). Reuses `HTTPTestSupport.TestClock`. 777 tests; ASan clean.
