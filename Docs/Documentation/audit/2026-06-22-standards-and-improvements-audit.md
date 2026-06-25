# Standards, CVE & Improvement Audit — 2026-06-22

A cross-protocol audit of the HTTP stack against the relevant RFC / CVE / ISO / BCP
corpus, identifying opportunities across **performance, memory safety & efficiency,
security, reliability, consistency, and coherency**. Every code claim carries a
`file:line`; every standards claim carries an RFC §/CVE/CWE.

Scope audited: HTTP/1.1 + semantics, HTTP/2, HPACK + Huffman, WebSocket, Transport +
TLS/ALPN + concurrency, HTTP/3 + QUIC + QPACK readiness, and the shared `HTTPCore`
currency types / hot paths. The HTTP/3 engine is milestone **M7 (not built)** — only the
test-only conformance catalog exists, so its section is forward-looking.

> Read-only audit. No source files were modified. The working tree had concurrent WIP
> (`Package.swift`, `ResponseSerializer.swift`, `HTTPServer.swift`, `WebSocketHandler.swift`)
> which was audited as-is but left untouched.

---

## 1. Overall posture

This is an unusually disciplined, standards-literate codebase. The zero-copy spine
(`ByteReader` as `~Escapable` over `RawSpan` with compiler-checked lifetimes), the
iterative (no-recursion) parsers, the typed-throws fail-closed error model, the two-scope
HTTP/2 error granularity, the HPACK decompression-bomb defenses, the request-smuggling
fundamentals, and the WebSocket framing MUSTs are all done correctly and are tested. The
currency-type design matches Apple's own `swift-http-types` reference.

The audit nonetheless surfaced **2 Critical**, **~13 High**, and a long tail of Medium/Low
findings. They cluster into five themes:

1. **Transport reliability is the weakest link.** A missing `SIGPIPE` guard makes the POSIX
   backbones killable by one packet; there is no global connection ceiling; the kqueue
   backbone mishandles `EINTR`/`EAGAIN` and leaks continuations on close. These are
   higher-impact than any single protocol-parser bug.
2. **The newest surfaces are the least hardened.** WebSocket (just landed) has no CSWSH
   defense and several §5.5/§8.1 state-machine gaps; ALPN-negotiated h2-over-TLS now
   *exposes* HTTP/2 DoS gaps over the encrypted path.
3. **Limits are not applied coherently across protocols.** `maxFieldCount`/`maxFieldSize`
   are enforced in HTTP/1 but **not** in HPACK decode or the HTTP/2 mapper — a header-count
   bomb bypass.
4. **The anti-DoS rate limiters are counters, not rate limiters.** The Rapid-Reset and
   control-frame budgets never decay (the `NowProvider`/`streamResetInterval` infrastructure
   built for exactly this is unused), and server-*emitted* RST_STREAM isn't counted at all
   (MadeYouReset bypass).
5. **Hot-path allocation & scalar byte loops** leave measurable throughput on the table
   versus the 200k-rps target: O(n) `HTTPFields` lookup, O(n) HPACK table insert, bit-at-a-
   time Huffman decode, per-byte WebSocket unmask, and several missing `reserveCapacity`s.

A documentation-accuracy issue compounds the picture: **`Documentation/Security.md` is
stale in both directions** — it lists three HTTP/2 defenses as "Pending" that are in fact
implemented (Rapid-Reset counter, `maxConcurrentStreams`, inbound flow control) and TLS/ALPN
as "Pending" though it is implemented, while the *genuine* current gaps (below) are absent.

---

## 2. Standards / CVE / norms register

The corpus this stack must track, and where it stands.

### Protocol & semantics RFCs
| Standard | Title | Status here |
|---|---|---|
| RFC 9110 | HTTP Semantics | Implemented (currency types, field/validation, methods, status) |
| RFC 9111 | HTTP Caching | Not started (affects `Date`/age — see C4) |
| RFC 9112 | HTTP/1.1 | Implemented incl. smuggling defenses; gaps in chunked runtime (H1-F1/F2/F3) |
| RFC 7541 | HPACK | Implemented; count-bomb + perf gaps (HP-F1/F2) |
| RFC 9113 | HTTP/2 | Implemented (request+response path); DoS-decay & MadeYouReset gaps (H2-F1/F2) |
| RFC 9114 | HTTP/3 | **M7 — not built**; catalog staged |
| RFC 9204 | QPACK | **M7 — not built**; Huffman/string primitives reusable from HPACK |
| RFC 9000 / 9001 / 9002 | QUIC transport / TLS / loss-recovery | Delegated to Network.framework `NWProtocolQUIC` |
| RFC 9218 | Extensible Prioritization | Not started (plan for SETTINGS/frame plumbing in M7) |
| RFC 9220 / 8441 | WebSocket over HTTP/2 (Extended CONNECT) | Not implemented (WS-F7) |
| RFC 6455 | The WebSocket Protocol | Framing implemented; CSWSH + state-machine gaps |
| RFC 7692 | permessage-deflate | Not implemented (reserved bits correctly rejected — safe) |
| RFC 9221 / 9297 | QUIC Datagram / HTTP Datagram (WebTransport) | Feasible on platform; post-M7 |
| RFC 8941 / 9651 | Structured Field Values | Not started (needed by 9218 priority, others) |
| RFC 6265bis | Cookies | Not started |
| RFC 7838 | Alt-Svc (advertise h3) | Not started |

### Security / crypto standards
| Standard | Relevance | Status |
|---|---|---|
| RFC 8446 | TLS 1.3 | Floor set to 1.3 (`NetworkFrameworkTLS.swift:63`) |
| RFC 9325 / BCP 195 | Secure use of TLS | Partially met; no max-version pin, no explicit cipher posture (T-F5) |
| RFC 7301 | ALPN | Advertised; no-overlap (`no_application_protocol`) not enforced (T-F6) |
| RFC 3629 + ISO/IEC 10646 | UTF-8 well-formedness | Validated (correct verdict); not incremental for WS text (WS-F3) |
| ISO 8601 vs IMF-fixdate | HTTP-date (RFC 9110 §5.6.7) | **No formatter exists** (C4); note: HTTP-date is *not* ISO 8601 |
| ISO/IEC 9899 (C) | `CHTTPTestMalloc` shim | Test-only; fine |

### CVE / CWE register
| ID | Class | Status in this stack |
|---|---|---|
| CVE-2023-44487 | HTTP/2 Rapid Reset | Counter present but **never decays**; not a true rate limit (H2-F2) |
| CVE-2024-27316 | HTTP/2 CONTINUATION Flood | **Defended** (count + size caps) ✓ |
| CVE-2025-8671 | HTTP/2 "MadeYouReset" | **Exposed** — server-emitted RST not counted (H2-F1) |
| CVE-2019-9511..9518 | HTTP/2 DoS family (Data Dribble, Ping/Settings/Reset/Empty-Frames flood) | Mostly mitigated; empty-frame/CONTINUATION cycle cost residual (H2-F6) |
| CVE-2016-6581 (+ 2025–2026 header-count "bomb" disclosures) | HPACK/HTTP-header count bomb | **Exposed** — `maxFieldCount` not enforced in HPACK/h2 (HP-F1, C2) |
| QPACK decompression / blocked-stream bombs | HTTP/3 (forward) | Must enforce field-section-size + blocked-streams in M7 (§9) |
| CWE-444 | Request smuggling (CL.TE/TE.CL/TE.TE/CL.0) | Core defenses correct ✓; chunk-ext/trailer residue (H1-F2/F3) |
| CWE-113 | Response splitting / header injection | Defended by construction ✓ |
| CWE-407 | Algorithmic complexity DoS | Chunked re-decode O(n²) (H1-F1); quadratic WS drain (WS-F4) |
| CWE-346 / CWE-1385 | Origin validation / CSWSH | **Exposed** — no Origin check in WS handshake (WS-F1) |
| QUIC amplification / 0-RTT replay (RFC 9000 §8 / RFC 9001 §9.2) | HTTP/3 (forward) | Amplification = platform; 0-RTT replay = our policy (§9) |

---

## 3. Prioritized findings (all areas)

Severity reflects exploitability × blast-radius for security/reliability items, and
throughput/clarity impact for performance/coherency items. IDs: **H1**=HTTP/1.1,
**H2**=HTTP/2, **HP**=HPACK/Huffman, **WS**=WebSocket, **T**=Transport/TLS, **C**=cross-cutting,
**H3**=HTTP/3 readiness.

### Critical
| ID | Finding | Dimension | Evidence | Standard |
|---|---|---|---|---|
| T-F1 | `write()` on a reset peer raises `SIGPIPE` → **process kill** (no `SO_NOSIGPIPE`/`MSG_NOSIGNAL`/`SIG_IGN` anywhere) | reliability, security (DoS) | `POSIXShared/POSIXSocket.swift:30-64`; `POSIXKqueue/…Connection.swift:116`; `SwiftSystem/…Connection.swift:128`; grep: none | POSIX.1-2017 `write(2)` |
| WS-F1 | No `Origin` validation or hook → **cross-site WebSocket hijacking** (CSWSH) | security (authz) | `WebSocket/WebSocketHandshake.swift:26-46`; grep: no `origin` | RFC 6455 §4.2.1/§10.2; CWE-346/1385 |

### High
| ID | Finding | Dimension | Evidence | Standard |
|---|---|---|---|---|
| H2-F1 | "MadeYouReset": engine-emitted RST_STREAM not rate-counted (WINDOW_UPDATE+0, PRIORITY len/​self-dep, post-END_STREAM frames all RST without counting) → Rapid-Reset mitigation bypassed | security, reliability | `HTTP2Connection.swift:205-211,414`; `+FlowControl.swift:153-160` | CVE-2025-8671; RFC 9113 §5.4 |
| H2-F2 | Rapid-Reset + control-frame budgets are monotonic counters that **never decay** (`streamResetInterval`/`NowProvider` unused) → bypass over time *and* false-positive on long-lived conns | security, reliability | `HTTP2Connection.swift:84,304,414-419`; `HTTPLimits.swift:69`; grep: not wired | CVE-2023-44487 |
| HP-F1 / C2 | `maxFieldCount`/`maxFieldSize` **not enforced** in HPACK decode or HTTP/2 mapper → header-count bomb (thousands of 1-byte indexed refs / Cookie crumbs under the byte budget) | security, coherency | `HPACKDecoder.swift:36-58`; `HTTP2RequestMapper.swift:24-58`; only `HeaderParser.swift:50` enforces | RFC 7541 §7; RFC 9113 §8.2.3; CVE-2016-6581 class |
| H1-F1 | Chunked body **re-decoded from offset on every socket read** → O(n²) CPU + repeated full-body allocations (up to `maxBodySize`=1 GiB) | performance, reliability, security | `HTTPServer.swift:422-446` calling `ChunkedDecoder.decode` per read | CWE-407; RFC 9112 §7.1 |
| H1-F2 | No bound on **chunk-extension** length (parser skips `;`→CRLF unboundedly); chunk count unbounded | security, reliability | `ChunkedDecoder.swift:27,68` | RFC 9112 §7.1.1 |
| H1-F3 | Chunked **trailer fields size-bounded but never grammar-validated** (no token/CRLF/NUL/obs-fold checks) — asymmetric vs header path | security, consistency | `ChunkedDecoder.swift:83-104` | RFC 9112 §7.1.2; RFC 9110 §5.5 |
| WS-F2 | Ping answered with Pong **even after a Close was received** | reliability, consistency | `WebSocketConnection.swift:119-135,178-181` | RFC 6455 §5.5.2 |
| WS-F3 | No **incremental UTF-8 validation** across fragments (validated only at end) → buffers up to 16 MiB of invalid text before rejecting; Autobahn 6.4.x non-strict | security (DoS), reliability | `WebSocketConnection.swift:161-174,209-212` | RFC 6455 §8.1; RFC 3629 |
| WS-F4 | `drainFrames` uses `inbound.removeFirst(consumed)` → **O(n) memmove per read** → quadratic under dribbled frames | performance, availability | `WebSocketConnection.swift:60-71,216-233` | CWE-407 |
| T-F2 | **No global connection/FD ceiling**; `withDiscardingTaskGroup` spawns one unbounded task per accept; only per-host cap exists | reliability, security (DoS) | `HTTPServer.swift:53-60`; `HTTPLimits.swift:73-95` | DoS hardening |
| T-F3 | kqueue read/write treat **`EINTR`/`EAGAIN` as fatal** (other 3 backbones retry) → spurious connection failures + coherency drift | reliability, coherency | `POSIXKqueue/…Connection.swift:99-101,120-123` | POSIX.1-2017 |
| T-F4 | Per-client cap applied **after** TLS handshake and keyed on spoofable host; ignores h2 stream multiplexing | security (DoS) | `HTTPServer.swift:67-84`; `NetworkFrameworkTransport.swift:114-121` | DoS defense-in-depth |
| HP-F2 / C10 | Huffman decode is **bit-at-a-time** (prod decoders use multi-bit table-driven, ~2×); WS unmask is per-byte with in-loop branch | performance | `HTTPCore/Huffman.swift:123-151`; `WebSocketFrameDecoder.swift:107-118` | perf (RFC 7541 App. B) |
| C1 | `HTTPFields` lookup is **O(n) linear scan with String compares**; ~5 full scans/request in framing resolution (reference impl uses a hashed index) | performance, coherency | `HTTPCore/HTTPFields.swift:34-66`; hit repeatedly in `RequestParser.swift:75-100` | perf; cf. swift-http-types |
| C3 | `HPACKDynamicTable.add` uses `entries.insert(at: 0)` → **O(n) memmove per inserted field** (decode + encode) | performance | `HPACK/HPACKDynamicTable.swift:55-60` | perf |

### Medium (condensed)
| ID | Finding | Dimension | Evidence |
|---|---|---|---|
| H2-F3 | Trailers bypass pseudo-header/field validation (`:status` in trailers accepted) — *staged F3* | security, consistency | `HTTP2Connection.swift:385-399` |
| H2-F4 | `Security.md` "Pending" table materially wrong (3 h2 defenses + TLS already implemented; real gaps absent) | consistency, coherency | `Security.md:71-75` vs code |
| H2-F5 | Second HEADERS w/o END_STREAM is a *connection* error; §8.1 wants a *stream* error — *staged F2* | consistency | `HTTP2Stream.swift:48-57` |
| H2-F6 | Empty/zero-length CONTINUATION-frame flood not separately bounded | security, performance | `HTTP2HeaderBlockAccumulator.swift:79-86` (CVE-2019-9518) |
| H1-F4 | No `Expect: 100-continue` handling → stalls compliant clients; pause-desync/RUDY seam | reliability, security | grep: none; `HTTPServer.swift:205` |
| H1-F5 | `Transfer-Encoding` accepted on HTTP/1.0; unknown TE → 400 not 501 | consistency, security | `RequestParser.swift:96-104` (RFC 9112 §6.1) |
| H1-F6 | `Connection`/`Upgrade` token parsing via `split`/`trimmingCharacters` allocates per request | performance | `HTTPServer.swift:496-503`; `HTTPServer+WebSocket.swift:22-30` |
| T-F5 | No TLS **max-version pin**; cipher posture unmanaged; 1.3 floor not configurable (rejects 1.2-only clients) | security | `NetworkFrameworkTLS.swift:63` (BCP 195) |
| T-F6 | ALPN **no-overlap not enforced** (`no_application_protocol` not sent — platform won't); `negotiatedApplicationProtocol` contract drift on TLS+nil | security, coherency | `NetworkFrameworkTLS.swift:54-70`; `HTTPServer.swift:100-123` (RFC 7301 §3.2) |
| T-F7 | kqueue **continuation leak**: fd closed while a `waitReadable`/`waitWritable` is parked → leaked task + retained buffers (triggered by the very Slowloris-timeout defense) | reliability, memory | `POSIXKqueue/…Connection.swift:52-82`; `KqueueEventLoop.swift:63-71` |
| T-F8 | `EMFILE`/`ENFILE` handled with `usleep(10ms)` **on the shared accept/event-loop queue** → freezes all connections under FD pressure | reliability, performance | `POSIXShared/POSIXSocket.swift:103-105` |
| T-F9 | `withTimeout` spawns a task group + clock-sleep task **per receive** on the hot path | performance | `HTTPServer.swift:317-332` |
| T-F10 | ALPN-h2-over-TLS now *exposes* the pending h2 DoS gaps over the encrypted path | security, consistency | `HTTPServer.swift:100-104` + H2-F2 |
| HP-F3 | `tableSize` (+32) bounds wire/eviction cost, not *materialized allocation* count (the bomb dimension) | security, memory | `HPACKField.swift:29-31` |
| HP-F4 / C5 | Decoded `[HPACKField]`/`HTTPFields`/`responseFields` arrays **never `reserveCapacity`** → COW regrowth per request | performance | `HPACKDecoder.swift:38`; `HeaderParser.swift:28`; `HTTP2Connection+Response.swift:47` |
| HP-F5 | Non-Huffman literal in `HPACKString.decode` still double-copies via `Array($0)` | performance | `HPACKString.swift:43` |
| HP-F6 | Encoder dynamic-table lookup is O(n) linear scan w/ closure per field (decoder side is O(1)) | performance, coherency | `HPACKEncoder.swift:50-57`; `HPACKDynamicTable.swift:44-49` |
| WS-F6 | Outbound close path doesn't validate caller-supplied code (`WebSocketCloseCode(rawValue:)` public+unvalidated) → can send 1005/1006 on wire | reliability, consistency | `WebSocketConnection.swift:97-104` (RFC 6455 §7.4.1) |
| WS-F7 | RFC 9220 (h2 Extended CONNECT) unsupported; handshake hard-requires GET; no `:protocol` on `HTTPRequest` | coherency | `WebSocketHandshake.swift:29` |
| WS-F8 | `inbound` buffer unbounded across partial frames (slow-frame DoS; pairs with WS-F4) | availability | `WebSocketConnection.swift:60-71` |
| C4 | **No RFC 9110 §5.6.7 HTTP-date (IMF-fixdate) formatter** anywhere → `Date` header can't be auto-emitted; each engine will reinvent | coherency, reliability | grep: only the `.date` name constant |
| C6 | h2 `respond` rebuilds `[HPACKField]` from currency types every response (extra modeling layer vs h1) | performance, coherency | `HTTP2Connection+Response.swift:46-52` |
| C7 | `HTTP2FrameWriter` GOAWAY/WINDOW_UPDATE/RST build throwaway `[UInt8]` via `+` (per-stream hot) | performance | `HTTP2FrameWriter.swift:49-72` |
| C8 | Registered `HTTPFieldName.rawName` re-bridges `StaticString.description` (alloc) per access (reference stores a `String`) | performance, coherency | `HTTPFieldName.swift:35-40` |
| C9 | `HTTP2RequestMapper.forbiddenFields` is `Set<String>`; ~5 passes over each field name; divergent from h1 name path | performance, coherency | `HTTP2RequestMapper.swift:19-21,94-103` |
| H3-cat | Catalog missing ~11 RFC 9114/9204 MUST gaps (server-push-stream, SETTINGS-on-request, reserved-settings breadth, two un-covered QPACK code triggers); one paraphrased title; 3 loose §-tags | consistency | `H3ConformanceCatalog.swift:225-278` (registries are wire-perfect ✓) |

### Low / Info (selected)
`H1-F7` header-accumulation cap can overshoot one 16 KiB read (`HTTPServer.swift:241-245`) ·
`H1-F8` Content-Length body copy + `removeFirst` memmove (`HTTPServer.swift:418-419`) ·
`H1-F9` no `Date`/`Server` on responses (RFC 9110 §6.6.1) ·
`H2-F7` frame on closed stream → PROTOCOL_ERROR not STREAM_CLOSED (*staged F1*) ·
`H2-F8` reset & control-frame budgets share one knob ·
`H2-F9` per-frame payload `Array` copy in decoder (`HTTP2FrameDecoder.swift:55`) ·
`H2-F10` encoder dynamic-table size never tracks peer SETTINGS_HEADER_TABLE_SIZE ·
`HP-F7` `Huffman.encode` undersized `reserveCapacity` ·
`C11` SWAR `memchr` opportunity in `ByteReader.firstIndex(of:)` (underlies every h1 parse) ·
`C12` `HTTPMethod` compares by String, not interned tag ·
`C13` h1 value validated *after* String materialization ·
`C14` `HTTP2HeaderBlockAccumulator.begin` copies fragment on single-frame fast path ·
`C15` Content-Length via `"\(body.count)"` interpolation ·
`T-F11` dev TLS identity uses RSA-2048/SHA-1 PKCS#12 via `openssl` subprocess (test-only) ·
`T-F12` POSIX backbones IPv4-only (`inet_pton(AF_INET)`) — coherency drift vs Network.framework ·
`T-F14` hardcoded `listen(…,128)`; no `SO_REUSEPORT`/`TCP_NODELAY`.

---

## 4. HTTP/1.1 + semantics

**Already excellent (keep):** CL+TE → 400 + `close` (RFC 9112 §6.3); `chunked`-only, no
compound/duplicate codings; defensive Content-Length incl. comma-list disagreement; obs-fold
+ bare-CR + whitespace-before-colon rejected; request-target validated on the borrowed span
before materialization; exactly-one-`Host`; field-value CR/LF/NUL rejected by construction
(`HTTPField.init?`); overflow-checked chunk-size; cumulative `headerReadTimeout` Slowloris
defense; correct HEAD/1xx/204/304 framing.

**Act on:** H1-F1 (incremental/resumable chunked decoder — the single highest-value h1 fix),
H1-F2 (bound chunk-ext length + chunk count), H1-F3 (validate trailer field-lines through the
same grammar as headers, even if discarded), H1-F4 (`Expect: 100-continue`), H1-F5 (reject
TE on 1.0; unknown TE → 501).

---

## 5. HTTP/2

**Already excellent (keep):** exemplary two-scope error model (connection→throw+GOAWAY before
re-throw; stream→RST_STREAM, continue); HPACK kept in sync on stream errors (decode-then-
reject); CONTINUATION flood genuinely defended (CVE-2024-27316); decompression-bomb interplay
sound; overflow-safe + signed-correct flow control (incl. §6.9.2 INITIAL_WINDOW_SIZE delta);
frame-size/padding validation before allocation; server hygiene (ENABLE_PUSH off, PUSH_PROMISE
rejected, unknown frames/settings ignored); honest `withKnownIssue` staging.

**Act on (the unifying fix):** Findings H2-F1, H2-F2, H2-F6, H2-F7, H2-F8 all converge on
**one time-windowed "abusive-frame budget"** that counts client RST, **server-emitted RST**,
control frames (PING/SETTINGS), and empty/zero-length frames, decayed over
`streamResetInterval` via the existing `NowProvider`/`TestClock` seam. Implementing that single
mechanism closes MadeYouReset, the missing rolling window, the empty-frame flood, the F1-fix
regression risk, and the conflated-knob issue together — and finally connects infrastructure
that already exists for exactly this purpose. Then fix H2-F3/F5 (trailers = stream-scoped
validation/error) and correct `Security.md`.

---

## 6. HPACK + Huffman

**Already excellent (keep):** §5.1 integer overflow guard (bound-before-add + `shift<32`);
§5.2 EOS/padding enforcement tested against Appendix C; dynamic-table §4.1/§4.3/§4.4 accounting
exact; combined index space (§2.3.3) correct; tables generated from the RFC; no recursion;
the recent "literals straight to String" decode path; shared Huffman in HTTPCore (QPACK-ready).

**Act on, in order:** HP-F1 (add the `maxFieldCount` guard to the decode loop — one line,
highest security ROI, closes the count-bomb), HP-F2 (replace bit-at-a-time Huffman with an
8-bit table-driven FSM, benchmarked via the existing cold/warm decode benchmarks — shared with
future QPACK), C3 (ring-buffer / append-oldest-first dynamic table — `Deque` from the already-
present swift-collections), HP-F4 (`reserveCapacity`), HP-F6 (hashed encoder index).
**Forward-looking coherency:** move `HPACKString` beside `Huffman` in HTTPCore and design the
prefix-integer codec for QPACK's 62-bit range before M7.

---

## 7. WebSocket

**Already excellent (keep):** RSV-bit + reserved-opcode rejection; minimal-length encoding;
64-bit high-bit guard; control-frame size/non-fragmentation; mandatory client masking on the
server + server frames never masked; fragmentation state machine; close-payload structure +
close-code validity (stricter-than-RFC range is correct for Autobahn 7.9.x — document it so it
isn't "helpfully" widened); §1.3 handshake vector exact; token parsing per RFC 9110 §5.6.1;
zero force-unwraps; probe-on-copy partial frames.

**Act on before any production exposure:** WS-F1 (CSWSH — add an `Origin` allowlist hook,
fail-closed for browser clients, `403`), then the reliability trio WS-F2 (suppress Pong after
Close), WS-F3 (incremental UTF-8 — also serves the Close reason and lets you drop the end-of-
message re-walk), WS-F6 (validate outbound close code). WS-F4 (quadratic drain) before the
200k-rps claim is load-bearing. WS-F7 (RFC 9220) and WS-F11 (subprotocols) are scoped features.

---

## 8. Transport + TLS + concurrency

**Already excellent (keep):** bounded, fail-closed unsafe TLS interop (`SecIdentity` type-checked
before `unsafeDowncast` — sound use, respects no-`as!`); TLS 1.3 floor set explicitly;
`OnceResumer` (correct `Mutex`-backed once-only continuation); swift-system cancellation via
off-queue `shutdown(2)` with an atomic guard (the one path with a real cancellation test);
kqueue close-on-loop-queue (avoids fd-reuse race); relaxed-atomic connection IDs; genuine
`Sendable` (no gratuitous `@unchecked`); the h1 read-loop hardening.

**Act on:** T-F1 (SIGPIPE — set `SO_NOSIGPIPE` per-fd or one-time `signal(SIGPIPE, SIG_IGN)` at
transport init — the single most impactful fix in the whole audit), T-F2/T-F4 (global
connection ceiling + accept-time/pre-handshake cap), T-F3 (kqueue `EINTR` retry / `EAGAIN`
re-arm — restores four-backbone parity), T-F7 (drain pending continuations in
`closeDescriptor`), T-F8 (move the `usleep` off the shared queue). Then BCP-195 polish:
T-F5 (max-version pin + configurable floor) and T-F6 (strict ALPN-overlap enforcement, since
the platform won't send alert 120). Reconcile `Security.md` TLS/ALPN status.

---

## 9. HTTP/3 + QUIC + QPACK readiness (M7)

The library will **ride Network.framework's QUIC** (`NWProtocolQUIC`): the whole QUIC
transport (RFC 9000) + QUIC-TLS (RFC 9001) + loss/cc (RFC 9002) layer — and thus the **34
QUIC/TLS h3spec checks** — are the platform's responsibility, not engine-testable against our
code. Only the **15 HTTP/3+QPACK checks + the RFC gaps** are M7 drive-and-assert targets.

**Catalog audit:** error-code registries are **wire-perfect** (RFC 9114 §8.1 0x0100–0x0110 ×17;
RFC 9204 §6 0x0200–0x0202 ×3) ✓. To do before M7 goes live: add ~11 missing MUST gaps
(server-receives-push-stream → H3_STREAM_CREATION_ERROR; SETTINGS-on-request → H3_FRAME_UNEXPECTED;
reserved-HTTP/2-settings breadth → H3_SETTINGS_ERROR; the two un-covered QPACK code triggers —
encoder-stream eviction → QPACK_ENCODER_STREAM_ERROR, KRC overflow → QPACK_DECODER_STREAM_ERROR);
quote the QPACK critical-stream title verbatim and split the conflated control-vs-encoder-stream
case; tighten 3 `section` tags; mark the 34 transport/TLS entries "transport-owned".

**M7 engine reuse wins:** RFC 7541 Huffman verbatim (RFC 9204 §4.1.2 mandates the same table —
the existing `Sources/HTTPCore/Huffman.swift` *is* it); HPACK integer/string primitives;
**mirror the HTTP/2 dual-error-granularity model** (note H3_MESSAGE_ERROR §4.1.2 and
H3_CONNECT_ERROR §4.4 are *stream* errors, the rest connection) with `RawValue = UInt64`.
Per-stream `NWConnection` from `NWConnectionGroup.newConnectionHandler` is the exact sans-I/O
byte boundary; emit our `H3ErrorCode` via `NWProtocolQUIC.ApplicationError`. **Platform risks:**
server-side QUIC has documented sharp edges (hidden initial stream; server-initiated stream
acceptance); stick to `NWProtocolQUIC`/`NWConnectionGroup` (macOS 12+), not the macOS-26
`QUIC.Stream` API.

**Security checklist (engine-owned):** rate-limit stream creation + resets → H3_EXCESSIVE_LOAD
(0x0107) — the H3 home for Rapid-Reset; enforce `SETTINGS_MAX_FIELD_SECTION_SIZE` incrementally
(decompression bomb); enforce `SETTINGS_QPACK_BLOCKED_STREAMS` → QPACK_DECOMPRESSION_FAILED;
**disable 0-RTT for M7** (or reject non-idempotent methods in early data — RFC 9001 §9.2);
GOAWAY monotonicity + Push-ID ≤ MAX_PUSH_ID → H3_ID_ERROR; critical-stream close →
H3_CLOSED_CRITICAL_STREAM. Amplification + stream/flow-control limits are platform-enforced —
we only set sane initial values.

---

## 10. Cross-cutting performance, memory & coherency

**Already excellent (keep):** the `ByteReader` zero-copy primitive (lifetime annotations correct
vs SE-0488; bounds-checked accessors; `Copyable` look-ahead used correctly); single-
materialization-boundary discipline (hostile input fails before any heap); `HTTPFieldName`
canonical-name design matching swift-http-types; the *measured* "no lookup table in
FieldValidation" decision; `HTTP2FrameWriter.drain()` swap; Huffman `unsafeUninitializedCapacity`
paths; the `expectAllocations` perf-guard methodology + per-CVE-annotated `HTTPLimits`.

**Coherency scorecard (h1 vs h2 over shared currency types):** the *types* are genuinely shared
and uniform; the divergences are in *enforcement* and *construction* — C2 (limits not applied in
h2), C6 (extra `[HPACKField]` layer on h2 response), C8/C9 (registered-name bridging + divergent
field-name validation paths), C13. Closing those makes "same currency types, built the same way,
limits applied identically" fully true **before** the h3 engine lands and forks the pattern again.

**Highest-leverage perf items (all gated on the project's "benchmark positively" rule):** C1
(hashed `HTTPFields` index or precomputed name hash), C3 (ring-buffer dynamic table), HP-F2
(table-driven Huffman), C10 (SWAR/SIMD WebSocket unmask, word-at-a-time), C11 (SWAR `memchr` in
`ByteReader.firstIndex` — underlies every h1 parse), and the `reserveCapacity` sweep (HP-F4/C5).
Add allocation ceilings (`expectAllocations`) to the parser hot paths to lock each fix in.

**Norms correctness note:** add an allocation-light IMF-fixdate formatter in HTTPCore (C4) —
HTTP-date is RFC 9110 §5.6.7, **not** ISO 8601, and must be `en_US_POSIX`/GMT (never localized);
cache per whole-second tick.

---

## 11. Documentation accuracy (`Documentation/Security.md`)

The security doc is stale and should be reconciled (it currently mis-states the posture in both
directions, which erodes its value as a trust artifact):

- **Move from "Pending" → "Implemented":** HTTP/2 Rapid-Reset *counter* (`HTTP2Connection.swift:414-419`,
  noting it is not yet a *rolling-window rate* — H2-F2), `maxConcurrentStreams` enforcement
  (`:368-371`), inbound flow control (`HTTP2Connection+FlowControl.swift` — not a no-op), and
  TLS/ALPN (`NetworkFrameworkTLS.swift`, with the BCP-195 caveats T-F5/T-F6). The h1 header-
  accumulation cap is also now implemented (`HTTPServer.swift:241-245`).
- **Add to "Pending":** T-F1 (SIGPIPE), T-F2/T-F4 (global ceiling), H2-F1 (MadeYouReset
  CVE-2025-8671), H2-F2 (reset rolling-window), HP-F1/C2 (header-count bomb), WS-F1 (CSWSH),
  WS-F2/F3 (Ping-after-Close, incremental UTF-8), and the h1 chunked items (H1-F1/F2/F3).

---

## 12. Recommended sequencing

1. **Stop-the-bleeding (Critical):** T-F1 SIGPIPE guard; WS-F1 Origin/CSWSH hook.
2. **DoS hardening (High):** the unified HTTP/2 abusive-frame budget (H2-F1/F2/F6/F7/F8);
   HP-F1/C2 `maxFieldCount` across HPACK+h2; T-F2/T-F4 global connection ceiling; H1-F1
   incremental chunked decoder + H1-F2 chunk-ext bound; WS-F2/F3/F4.
3. **Reliability/coherency (High→Medium):** T-F3 kqueue EINTR, T-F7 continuation leak, T-F8
   usleep; H1-F3 trailer validation; H2-F3/F5 trailers scope; reconcile `Security.md`.
4. **Performance (benchmark-gated):** C1, C3, HP-F2, C10, C11, the `reserveCapacity` sweep; add
   allocation ceilings to lock them in.
5. **Standards polish + M7 prep:** BCP-195 TLS (T-F5/F6); HTTP-date formatter (C4); h1 100-continue
   (H1-F4) + TE/501 (H1-F5); RFC 9220 if h2 WS is in scope; finalize the H3 catalog gaps and the
   shared-primitive refactor (Huffman/string/integer) ahead of the M7 engine.

---

*Compiled from seven parallel specialist audits (HTTP/1.1, HTTP/2, HPACK/Huffman, WebSocket,
Transport/TLS/concurrency, HTTP/3 readiness, cross-cutting perf/coherency), each cross-
referencing the code against the RFC/CVE/BCP/ISO corpus. Key load-bearing claims (SIGPIPE
absence, CSWSH absence, `maxFieldCount` non-enforcement, Rapid-Reset non-decay,
`maxConcurrentStreams` enforcement, trailers validation gap) were independently re-verified
against the source.*
