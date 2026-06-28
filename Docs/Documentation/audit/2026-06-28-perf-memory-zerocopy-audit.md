# Performance / memory-safety / zero-copy / COW audit — 2026-06-28

A whole-codebase audit through the *performance · memory safety · copy-on-write tax · zero-copy ·
convolution* lens (the "what would Carmack or Torvalds flag" brief), the natural successor to the
[overdefensive/security audit](2026-06-28-overdefensive-antipattern-audit.md), which deferred the perf
items (F10/F11) as benchmark-gated future work. Goal bar is `CLAUDE.md`: **200k rps, minimal allocation,
zero-copy, no COW tax, SIMD/SWAR when benchmarked, cyclomatic < 15, ≤400 lines/file.**

**Method.** An atomic cross-cut (global signal counts for allocation/copy/unsafe/COW/zero-copy-API
patterns across the whole tree), then **3 parallel read-only scope audits** (byte/codec core · transport
socket+TLS floor · server/auth/observability). **Every Tier-1/2 candidate was then re-verified against the
real source by hand** — and, as in prior audits, that step mattered: most of the agents' "Critical/High"
findings did not survive it. Vendored BoringSSL (`Sources/Core/CHTTPBoringSSL*`) was excluded as third-party.

## Headline

An **exceptionally well-optimized codebase already.** The parsers are zero-copy by construction
(`ByteReader` is `~Escapable` over a borrowed `RawSpan`, with `@_lifetime`); SWAR validators carry
*recorded* benchmarks and explicit notes rejecting a lookup table (2–3× slower) and `memchr` for short
delimiters; the F10 allocation trims are already in place (`HTTPDate` one-buffer, `QueryParameters`
fast-path); there are **no force-unwraps / `try!` / `as!` and no memory-safety defects.** The real wins
are a **small, surgical set** — led by one true headline (a per-read allocation+copy on the I/O hot path).

## Confirmed findings

Hotness: **Hot** = per-request/frame/byte · **Warm** = per-connection · **Cold** = startup/config.

| ID | Tier | Hot | Category | Location | Issue → Fix |
|----|------|-----|----------|----------|-------------|
| **P1** | 1 | Hot | Alloc + ZeroCopy | `Server/HTTPServer/HTTPServer+RequestReader.swift:147-170` (+ 4 sibling loops) | Every `recv` allocates a fresh 16 KB `[UInt8]` then `buffer.append(contentsOf:)` copies it into the accumulator and discards it. → Add `receive(into:maxLength:)` to `TransportConnection` (copying default for Network/fakes), override on the POSIX backbones + PortableTLS to read into a **reused per-connection scratch**, and parse from the scratch directly on the single-read common case. Benchmark kqueue-first. |
| **P2** | 2 | Warm | Alloc | `HTTPAuth/Base64URL.swift:18-36` | base64url decode does ~5 allocations + pulls in Foundation (two `replacingOccurrences`, a `+=` pad loop, `Data(base64Encoded:)`, `[UInt8](data)`). → One-allocation URL-alphabet decode. ⚠ benchmark vs Foundation; keep the winner. |
| **P3** | 2 | Warm | Alloc | `Core/HTTPCore/StructuredFields+Serialization.swift:125,136` | `Array(token.utf8)` / `Array(key.utf8)` materialized purely to validate. → Iterate the `.utf8` view directly. No behavior change. |
| **P4** | 2 | Warm | Alloc | `HTTPAuth/JWT.swift:136,148-163` | `Array("\(header).\(payload)".utf8)` rebuilds a string that is already a contiguous token slice; `Data(signature)`/`Data(signingInput)` re-wrap `[UInt8]` for swift-crypto. → Slice the token; pass `ContiguousBytes` directly. |
| **P5** | 2 | Hot* | Alloc | `Transport/.../PortableTLS/PortableTLSConnection.swift:130` | TLS receive zero-fills 16 KB then `removeLast`-trims. → `unsafeUninitializedCapacity` (mirror `POSIXSocket.readBuffer`). *gated to `HTTP_PORTABLE_TLS`. Folds into P1. |
| **P6** | 3 | Hot | Alloc / COW | `Server/HTTPServer/Routing/Route.swift:95,98` | `String(components[index])` per captured param + `.joined` for catch-all, per matched route. → Store `Substring` slices of the request path; materialize `String` lazily. Benchmark-gated. |
| **P7** | 3 | Warm | Alloc / InlineArray | `Transport/.../POSIXKqueue/KqueueEventLoop.swift:123` · `POSIXEpoll/EpollEventLoop.swift` | `[KEvent](repeating:_,count:64)` heap-allocates per `pollOnce()`. → `InlineArray<64, KEvent>` stack local (no heap, no Mutex). ⚠ verify base-pointer hand-off to `kevent`/`epoll_wait`. |
| **P8** | 3 | Warm | Alloc / COW | `Protocols/QPACK/QPACKEncoder+Dynamic.swift:84,89` · `Protocols/HPACK/HPACKDynamicTable.swift:68` | Insert-path `Array(field.*.utf8)`; `entries.insert(at:0)` is an O(n) shift. → Pass `.utf8`; newest-at-end O(1) insert. ⚠ small bounded table — benchmark to justify; may reject. |
| **P9** | 3 | Warm | Alloc | `Core/HTTPCore/QueryParameters.swift:63,104` | Slow-path `Array(slice.utf8)` can iterate the view; `request.query` re-parses per access (document/cache tradeoff). Low. |
| **P10** | 4 | — | Convolution | `Transport/.../POSIXKqueue/POSIXKqueueConnection.swift:154` (+ epoll/dispatch) | Write/read re-arm threads `offset` through nested static closures. → Extract a small `WriteState`/`ReadState`. Behavior/perf neutral. |
| **P11** | 4 | — | DRY | `HTTPAuth/Base64URL` · `Server/.../SessionMiddleware` · `StructuredFields` encoder | ≥3 base64 implementations. → One internal `Base64` util (folds P2). |
| **P12** | 4 | — | Budget | `Protocols/HTTP2/HTTP2Connection.swift` | 411 lines (>400). → Justify-note or split. |

## Rejected false positives (verified correct — do **NOT** "fix")

| Claim | Why it's wrong |
|---|---|
| `RequestParser.swift:99` body `Array($0)` is a double alloc | `slice(in:)` returns a **borrowed `RawSpan`** (`extracting`, zero-copy); `Array($0)` is the **single, unavoidable** materialization where the body becomes owned to escape into the async handler. Same for `RequestReader.swift:300`. |
| `QueryParameters.swift:63` allocates on the fast path | The F10 fast-path (`:57-62`) returns *before* `:63`; the `Array` is only the rare percent-decode slow path. |
| Router needs a trie / route-match SWAR | Over-engineering vs "minimal, allocation-light"; small tables, cache-friendly linear compare. SWAR was *measured non-winning* for short scans. |
| `HTTPFieldName.swift:68` double-pass lowercase | Deliberately optimized for the h2/h3 already-lowercase hot path; fusing the passes pessimizes the common case. |
| `FieldValidation` should use a 256-entry table | Benchmarked **2–3× slower** (Swift `static let` lazy-init guard) — noted at `:46-49`. |
| `ByteReader.firstIndex` should be SWAR/`memchr` | Benchmarked flat-to-regression for short HTTP delimiters — noted at `:116-124`. |
| Middleware chain builds nested closures per request | Composed **once** in `MiddlewareChain.init`; `respond` just calls into it. |
| Replace swift-crypto with buffer APIs | Already uses swift-crypto; the only nit is the redundant `Data` re-wrap (→ P4). |
| `HTTPDate` interpolation allocations | F10 already fills one 29-byte buffer via `String(unsafeUninitializedCapacity:)`. |

## Named-technique applicability (honest)

- **`Span`/`RawSpan`/`~Escapable`/`@_lifetime`** — already the core parsing model; net-new use is the receive-into tail (P1).
- **`InlineArray`** — one clean win (P7); marginal elsewhere.
- **SWAR / SIMD / Accelerate** — already applied where measured-positive, explicitly rejected where measured-negative; no new slam-dunk survived. Do not add speculatively.
- **Arena** — not idiomatic in Swift (no allocator param on `String`/`Array`); the realized equivalent is per-connection buffer reuse (P1/P5).
- **Zero-copy** — parsers already zero-copy to the single materialization boundary; the remaining avoidable copy is receive→accumulator (P1). Body/request `String` materialization is inherent to the async escape — kept.

## P13 — `Array(x.utf8)` / `String(...)` copies on pass-through paths (user-requested sweep)

Many `Array(someString.utf8)` and `String(substring)` materializations exist only to satisfy an API that
could take a **view**. Triage:
- **Genuine waste → fixed:** the QPACK insert path (`QPACKInstructions.insertWith*Name` now take
  `some Collection<UInt8>`, so `QPACKEncoder+Dynamic` passes `field.value.utf8`/`field.name.utf8`);
  `Base64.encode` takes `some Collection<UInt8>`; **JWT** decodes from `segments[i].utf8` (3 `String`
  temporaries removed) and **Session/BasicAuth** from `parts[1].utf8`.
- **Already view-friendly:** `Huffman.encode`, `HPACKString.encode`, `FieldValidation.isToken` already
  take `some Sequence/Collection<UInt8>`; the remaining `Array(...)` sites are tests (cosmetic).
- **Necessary materialization boundary → kept (NOT waste):** response bodies (`ServerResponse(body:)`,
  `FileResponder`, `ContentNegotiation`) and the queued WebSocket payload escape the source `String`'s
  lifetime, so they must own a `[UInt8]`; a `~Escapable` view cannot outlive the `String`.
- **Deferred candidate:** `StructuredFields.Parser` stores `Array(source.utf8)` for indexed parsing — a
  zero-copy `RawSpan`/`ByteReader` redesign (like the HTTP/1 parsers) is possible but is a larger refactor
  on a non-universal path.

## Remediation (tracking)

Every perf change is benchmark-gated (kept only on a positive delta) and TDD (red→green).

| ID | Status | Test / benchmark coverage |
|----|--------|---------------------------|
| P3 | ✅ Done | StructuredFields suite (24, incl. byte-seq round-trip + fuzz) green; `.utf8` view, no copy |
| P4 | ✅ Done | JWT suite (19) green; signing-input sliced from token, redundant `Data` re-wraps dropped |
| P2 | ✅ Done | New `Base64` suite + JWT; hand-rolled decoder **6.3× faster** than Foundation (4334→683 ns/op) |
| P5 | ✅ Done | gated `HTTP_PORTABLE_TLS` build clean; uninitialized read, no memset/trim |
| P11 | ✅ Done | One `HTTPCore/Base64` (std §4 + url §5, view-accepting encode); JWT/Session/StructuredFields/BasicAuth/WebSocket migrated; Foundation dropped from `SessionMiddleware`; full 968-test suite green |
| P13 | ✅ Done | QPACK insert + JWT/Session/BasicAuth decode pass `.utf8`/`Substring` views; `StructuredFields.Parser` re-backed on `~Escapable` `ByteReader` (no `Array(source.utf8)`); `JWT.verify` takes `some StringProtocol` (no `String(parts[1])`); digit-count arithmetic. 968-test suite green |
| P12 | ✅ Done | `HTTP2Connection` 411→383 lines; `receiveReset` → `+ControlFrames`; 212 HTTP/2 tests green |
| P9 | ✅ Done | `QueryParameters` slow path decodes off the `UTF8View` (no `Array(slice.utf8)`); suite green. Query re-parse-per-access kept (caching needs request mutability — documented tradeoff) |
| P10 | ⊘ Reject | The POSIX re-arm code is already cleanly factored (explicit `WriteOutcome` enum + cohesive `readAvailable`/`writeFrom`/`clearWaiter` helpers) — no convolution to fix; a `WriteState/ReadState` refactor would be churn + risk on the just-verified transport for no clarity gain |
| P1 | ✅ Done | `receive(into:maxLength:)` on `TransportConnection` (copying default for Network/Fake/Dispatch); kqueue/epoll/SwiftSystem/PortableTLS override with a reused `Mutex<[UInt8]>` scratch (no per-read 16 KB alloc — the read fills the scratch in the event-loop callback, resumes with the byte count, the task copies once into the accumulator). Continuation-boundary constraint resolved without a ByteBuffer redesign. Micro-bench: **74 → 14.5 ns/op (~5×)** on the read-buffer path; 968-test suite + gated `HTTP_PORTABLE_TLS` build green |
| P6 | ✅ Done | `RouteParameters` holds captured params as `Substring` slices of the request path; `String` materialized lazily on access (no per-param copy at match time). Router suite (18) green |
| P7 | ⊘ Skipped | `InlineArray` is `@available(macOS 26)`; at the macOS 15.6 floor it needs an `if #available` + `[KEvent]` fallback (a dual hot-loop path) — not worth it for a per-*poll* (not per-request) buffer. Revisit when the floor rises to 26 |
| P8 | ✅ Done | QPACK insert view pass-through (P13) **plus** a full `HPACKDynamicTable` rework: **(1)** growable **circular buffer** — add at the tail / evict at the head, both **O(1)**, replacing the per-insert `insert(at:0)` memmove (bench **~42 → ~6.9 ns/op, ~6×**). **(2)** Two **sequence-keyed hash indices** (`index(of:)` exact, `index(forName:)`) make the encoder's lookups **O(1)** — keyed on a monotonic insertion sequence so relative-index shifts and ring relocation never invalidate them; maintained on add/evict with newest-wins + duplicate-safe cleanup (bench **~4.5–8.5×** vs the linear scan at 64–128 entries; the common exact-**miss** for unique-value headers is the biggest win, 575 → 67 ns). `field(at:)` O(1); custom `==` compares live entries. A new differential test cross-checks the hash index against a brute-force scan through duplicates + eviction; RFC 7541 App. C + dynamic-table + h2spec + encoder/decoder all green. *(Re-evaluated end to end after the initial reject.)* |

**Verification (all green):** `HTTP_WARNINGS_AS_ERRORS=1 swift build` clean · `HTTP_PORTABLE_TLS=1 swift build`
clean · full suite **968 tests / 13 targets, 0 failures** · `swift format lint --strict` + `swiftlint`
clean on every changed file. Micro-benchmarks: base64url decode **6.3×** (P2), read-buffer path **~5×** (P1).

**Net:** 12 items shipped (P1–P6, P8, P9, P11–P13), 1 skipped (P7, availability), 1 rejected (P10 re-arm
refactor — the code is already cleanly factored). No memory-safety defect was found or introduced; the
parsers remain zero-copy and the SWAR/SIMD validators untouched.
