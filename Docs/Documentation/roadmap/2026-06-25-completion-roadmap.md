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

- [x] **P4 — Inbound decompression breadth.** `deflate` (raw + zlib-wrapped) + `brotli`
      (`COMPRESSION_BROTLI`), gzip `FLG≠0` header parsing + CRC-32/ISIZE verification; same bomb caps
      (CWE-409). _Gate:_ per-codec round-trip + bomb fuzz never-traps; ASan clean. ✓ 781 tests green.

- [x] **P5 — RFC 9111 response caching.** CacheMiddleware + bounded LRU `ResponseCache`: Cache-Control
      directives, freshness (§4.2), `Age` (§5.1), Vary key, byte-cap eviction. _Gate:_ freshness/Vary/
      eviction tests; no caching of uncacheable responses. ✓ 790 tests green; ASan clean. (Stale-entry
      revalidation deferred as a follow-up — see CacheMiddleware doc.)

- [~] **P6 — Streaming bodies (keystone).** Additive `ResponseStream` + `ResponseBodyWriter`;
      `ServerResponse.body` unchanged, `.stream`/`.serverSentEvents` opt-in. **P6a done:** native HTTP/1.1
      chunked streaming + SSE, middleware guards (Compression/Cache skip streams), h2/h3 finite-buffer
      fallback. ✓ 795 tests green (790 buffered unchanged), ASan clean.
      **P6b (deferred follow-up — native h2/h3 streaming):** h3 is tractable — per-stream tasks +
      QUIC transport backpressure already exist; add `HTTP3Connection.respondHeaders`/`dataFrame`, a
      per-stream `H3StreamWriter` (frames DATA, `stream.send(fin:false)`, FIN at end), plus a fake-QUIC
      test harness. h2 is the hard one: native streaming inside the multiplexed serve loop deadlocks
      (a producer running in an event handler can't read the `WINDOW_UPDATE` that reopens an exhausted
      send window), so it needs a concurrent producer task + serialized (actor/lock) engine access +
      window-coordinated backpressure. Deferred to its own focused, fully-tested effort rather than a
      rushed change; P6a's finite-buffer fallback keeps h2/h3 correct meanwhile.

- [x] **P7 — Static file serving.** FileResponder: traversal-safe (CWE-22), content-type via the system
      `UTType` registry, Last-Modified/ETag from mtime+size, native Range (reuse `RangeMiddleware.parse`)
      + conditional, large files streamed (P6a). _Gate:_ traversal rejected, validators, ranged/
      conditional/HEAD/index/streamed tests. ✓ 803 tests green; ASan clean.

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
- 2026-06-25 — P4 done: inbound `deflate` (raw + zlib) and `brotli` (`COMPRESSION_BROTLI`), gzip FLG
  header parsing + CRC-32/ISIZE verification; bomb caps unchanged, fuzz extended to all three decoders.
  781 tests; ASan clean.
- 2026-06-25 — P5 done: CacheMiddleware + bounded-LRU ResponseCache + CacheControl parser — fresh-hit
  with `Age`, Vary keying, no-store/private/no-cache handling, byte-cap eviction; registered `Age`,
  `Accept-Language`. 790 tests; ASan clean. Revalidation deferred.
- 2026-06-25 — P6a done: additive ResponseStream + ResponseBodyWriter; native HTTP/1.1 chunked streaming
  + SSE (`.streaming`/`.serverSentEvents`), middleware guards, h2/h3 finite-buffer fallback. Buffered
  path byte-identical (790 unchanged). 795 tests; ASan clean. P6b = native h2/h3 streaming (deferred).
- 2026-06-25 — P7 done: FileResponder — traversal-safe (CWE-22), `UTType` content types, mtime/size
  validators, conditional (304), native Range (206/416), index.html, large-file streaming via P6a.
  803 tests; ASan clean.
