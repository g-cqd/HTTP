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
      **P6b — native h2/h3 streaming:** ✓ **S2 (h3) done** — `HTTP3Connection.respondHeaders`/`dataFrame`
      + a per-stream `H3StreamWriter` (frames DATA, `stream.send(fin:false)`, empty FIN at end); HEAD
      sends headers+FIN; buffered path unchanged. QUIC streams are independent tasks with transport-level
      backpressure, so the producer drives the stream inline with no flow-control deadlock. _Gate:_ 6
      engine framing tests (respondHeaders/dataFrame/round-trip/untrack) + a real-QUIC loopback streaming
      integration test (no fake-QUIC harness exists, so the Network.framework loopback is the integration
      mirror); h3 conformance + full suite green; ASan clean. **S4 (h2) — engine API done, server
      adoption deferred (fallback retained).** The sans-I/O engine now has the incremental DATA API —
      `respondHeaders` (HEADERS, no END_STREAM), `sendBodyChunk` (append + window-bounded flush),
      `endStream` (final or empty END_STREAM DATA), `pendingBacklog` (backpressure signal) — proven
      deadlock-free and bounded by deterministic engine tests (a forced window stall across 20 chunks
      holds the backlog ≤ one chunk). The *server* stays on P6a's finite-buffer fallback: native wire
      streaming needs a producer task feeding the engine across a bounded handoff with the serve loop
      interleaving inbound reads, and the in-memory transport can't stage a late `WINDOW_UPDATE` to
      *prove* the orchestration deadlock-free — so per the highest-risk-phase rule the design is recorded
      and the fallback kept rather than rushing concurrent code into the "failsafe" runtime. **Recorded
      design:** run `stream.produce` in a child task that `put`s chunks into a 1-slot rendezvous
      (backpressure = producer ≤1 chunk ahead); the single serve loop `take`s a chunk only when
      `pendingBacklog == 0`, `sendBodyChunk` + flushes, and when window-blocked drains inbound
      (WINDOW_UPDATE → flush) until the backlog clears — single-threaded engine access (no actor/race),
      one-chunk-bounded, deadlock-free since the loop always reads inbound when blocked. Open risks:
      rendezvous continuation cleanup on early cancel; concurrent streaming on sibling streams (v1 would
      buffer those).

- [x] **P7 — Static file serving.** FileResponder: traversal-safe (CWE-22), content-type via the system
      `UTType` registry, Last-Modified/ETag from mtime+size, native Range (reuse `RangeMiddleware.parse`)
      + conditional, large files streamed (P6a). _Gate:_ traversal rejected, validators, ranged/
      conditional/HEAD/index/streamed tests. ✓ 803 tests green; ASan clean.

- [~] **P8 — Protocol depth.** _Research/design done (this session); implementation is deep, conformance/
      security-sensitive work to do with fresh context, each feature fully tested._
      - [x] **WebSocket permessage-deflate (RFC 7692) — S3 done.** `Sec-WebSocket-Extensions`
        negotiated + echoed (h1 `WebSocketHandshake`; RFC 8441 h2 `acceptTunnel`), `WebSocketFrame.rsv1`
        with the decoder allowing RSV1 only when negotiated — never on a control or continuation frame —
        and the encoder setting it, and `WebSocketConnection` compressing on send / inflating on receive
        with the inflated size hard-capped (CWE-409). **S3+ upgrade (bit-exact, done):** Apple's
        Compression `compression_stream_*` cannot emit a `Z_SYNC_FLUSH` (flags 0 buffers everything — 0
        bytes out; only FINALIZE flushes, with BFINAL — proven by probe), so the codec now drives raw
        DEFLATE through a `CWSDeflate` zlib C shim (zlib was already linked by CCRC32) — bit-exact RFC
        7692 §7.2.1 (`Z_SYNC_FLUSH`, strip `00 00 FF FF`) / §7.2.2 (re-append + inflate), with strict
        rejection of malformed DEFLATE. **Context-takeover** is now supported and negotiated per direction
        (`PermessageDeflateParameters`, honoring the client's `server`/`client_no_context_takeover`);
        a stateful per-connection codec carries the LZ77 window across messages. _Gate:_ bit-exact codec
        round-trip (text/binary/empty/50 KiB) + context-takeover (repeat compresses smaller) +
        no_context_takeover independence, engine receive/send, RSV1 without-negotiation / on-continuation /
        on-control rejected, bomb cap → close, negotiation accept/echo/decline/honor, +3 pmd fuzz; ASan
        clean. (Autobahn CI remains a P10 item.)
        ✓ 829.
      - [~] **QPACK dynamic table (RFC 9204) — S5: foundation done, integration deferred.** Landed the
        `QPACKDynamicTable` data structure — a separate-index-space FIFO with the §3.2.4–§3.2.6
        absolute-index / Base-relative / post-base / insert-point arithmetic (the known QPACK interop
        trap), §3.2.2 eviction (oldest-first, absolute indices preserved), capacity / Set Capacity, and
        Duplicate — with 9 unit tests pinning each conversion. The encoder/decoder/connection *integration*
        (encoder insert heuristic + encoder-stream instructions; decoder dynamic indexed/post-base refs,
        Required Insert Count validation, Section-Ack / Insert-Count-Increment; executing encoder-stream
        inserts in `parseQpackStream`; raising the SETTINGS) is the interop-sensitive remainder, deferred
        like S4: it touches the working, conformant static-only h3 decode path, and blocked-stream
        buffering / eviction-with-outstanding-references (§2.1.3) are the hardest HTTP/3 sub-problems —
        so the v1 static-only encoder/decoder stays operational as the mandated fallback, gated on
        QPACK/h3 conformance + fuzz + interop before it flips on. **Recorded integration plan:** advertise
        a non-zero `SETTINGS_QPACK_MAX_TABLE_CAPACITY` with `QPACK_BLOCKED_STREAMS = 0` first (no
        blocked-stream buffering — reject a section whose RIC exceeds received inserts), enhance only the
        *decoder* to consume a peer's dynamic-table usage (browsers compress requests), and keep our
        response *encoder* static-only (valid: each endpoint chooses its own encoder strategy).
      - [x] **Priority scheduling (RFC 9218) — S1 done.** h2 `StreamRecord.urgency` cached from the
        request's `Priority` field at stream creation; `flushAll` orders ready streams by ascending
        urgency (ties → lower stream id) so a congested connection releases higher-priority DATA first
        (§4). h3 is out of scope (independent per-stream tasks → no shared flush to order). _Gate:_ 3
        priority-order tests (later/earlier/equal-urgency); h2spec + full suite green; ASan clean. ✓ 806.
      _Gate (per feature):_ QPACK/h3 conformance + fuzz; a priority-order test; a pmd round-trip + bomb
      cap; h2spec still green.

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
- 2026-06-25 — P8/S1 done: RFC 9218 HTTP/2 priority scheduling — `StreamRecord.urgency` cached at stream
  creation from the `Priority` field; `flushAll` ordered by ascending urgency (lower stream id breaks
  ties) so a congested connection flushes higher-priority DATA first. h3 out of scope (per-stream tasks).
  806 tests; ASan clean.
- 2026-06-25 — P6b/S2 done: native HTTP/3 response streaming — `HTTP3Connection.respondHeaders` (QPACK
  HEADERS, no FIN, untracks the stream) + static `dataFrame`; `serveHTTP3Stream` drives a `ResponseStream`
  via an `H3StreamWriter` (DATA frames `fin:false`, then empty FIN), HEAD = headers+FIN. Buffered path
  unchanged. 6 engine framing tests + a real-QUIC loopback streaming integration test. 813 tests; ASan
  clean; h3 conformance green. (S4 native h2 streaming remains.)
- 2026-06-25 — P8/S3 done: WebSocket permessage-deflate (RFC 7692, `no_context_takeover`) — negotiate +
  echo `Sec-WebSocket-Extensions` (h1 + RFC 8441 h2), `WebSocketFrame.rsv1` (decoder allows RSV1 only
  when negotiated, never on control/continuation; encoder sets it), compress on send / inflate on receive
  with a CWE-409 size cap. New `PermessageDeflate` over Apple Compression: per-message FINALIZE stream
  (Compression cannot `Z_SYNC_FLUSH` — probed), decompress = append `00 00 FF FF` + inflate. 829 tests;
  ASan clean. Context-takeover + zlib-exact `Z_SYNC_FLUSH`/Autobahn interop deferred to P10.
- 2026-06-25 — P6b/S4 partial: native HTTP/2 streaming *engine* API landed — `HTTP2Connection`
  `respondHeaders` / `sendBodyChunk` / `endStream` / `pendingBacklog` (sans-I/O, deadlock-free; a forced
  20-chunk window stall keeps the backlog ≤ one chunk). Server adoption deferred per the highest-risk-phase
  rule: the in-memory transport can't stage a late WINDOW_UPDATE to prove the producer/loop orchestration
  deadlock-free, so the P6a finite-buffer fallback is retained and the single-task rendezvous design is
  recorded in P6b. 834 tests; ASan clean; h2spec green.
- 2026-06-25 — P8/S5 partial: QPACK dynamic-table *foundation* landed — `QPACKDynamicTable` (RFC 9204
  §3.2: separate index space, absolute / Base-relative / post-base / insert-point arithmetic, §3.2.2
  eviction, capacity, Duplicate) with 9 unit tests pinning the interop-trap arithmetic. Encoder/decoder/
  connection integration (inserts, dynamic refs, RIC, Section-Ack/ICI, blocked streams) deferred and
  recorded; static-only QPACK retained operational as the mandated fallback. 843 tests; ASan clean.
- 2026-06-25 — fix: deterministic Network.framework `boundPort` (captured at `.ready`), removing the rare
  BackboneConformanceTests "bound no port" flake under concurrent full-suite load.
- 2026-06-25 — P8/S3+ done: permessage-deflate is now bit-exact RFC 7692 over a new `CWSDeflate` zlib C
  shim (raw DEFLATE + `Z_SYNC_FLUSH`; zlib was already linked by CCRC32), replacing the Compression
  FINALIZE backend, with **context-takeover** negotiated per direction (`PermessageDeflateParameters`).
  846 tests; ASan clean.
