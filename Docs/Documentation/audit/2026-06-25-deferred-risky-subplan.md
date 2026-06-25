# Deferred / Risky Work — Design Sub-Plan (2026-06-25)

The campaign's safe work is complete and merged; what remains is **deferred-by-design, sibling-owned,
or delicate enough to require a measurement/security gate before any code lands**. This document is the
design + the gate for each — it deliberately ships **no risky code**. Execute an item only when its
gate is cleared.

## 1. HTTP/3 per-request allocations (24-malloc receive, 32-malloc respond)

**Finding.** The engine-level benchmarks put the h3 request path at ~24 allocations (per-field `String`
+ `HeaderField` materialization on receive) and the response path at ~32 (the `responseFields` rebuild
into `[HeaderField]` before QPACK encode). This per-request constant — not transport — is what gates the
h2/h3-over-TLS throughput gap measured in `2026-06-25-perf-battletest.md` §2.

**Design.** Move owned→borrowed on the encode side first (the lower-risk, higher-yield half):
- `QPACKEncoder.encode` today takes `[HeaderField]` (owned). Add an `encode(_:into:)`-style overload that
  consumes `HTTPFields` + the `:status` pseudo-header **directly**, writing into a caller buffer — no
  intermediate `[HeaderField]` array, no per-field `rawName`/value `String` allocations. Mirror the
  existing `Huffman.encode(_:into:)` shape.
- On receive, investigate borrowing field-name/value slices out of the decode buffer where the value's
  lifetime is bounded by the call, materializing `String` only for the values that escape into the
  dispatched `HTTPRequest`.

**Risk.** A QPACK encoder API change; `~Escapable`/lifetime correctness (a borrowed `RawSpan`/slice must
not outlive the buffer); HPACK/QPACK share code paths, so a regression could hit both.

**Gate (all required before merge).** (a) A `mallocCountTotal` benchmark on `http3/Connection/respond`
(and `receive`) showing the drop; (b) **zero** h3/QPACK conformance + fuzz regression; (c) no new escape
(ASan + the compiler's lifetime checks). No merge on a guess — the Iron Law applies.

**Recommendation.** Worth doing, as its own measured branch, encode side first. Sequence: pin the exact
alloc count with `expectAllocations`, refactor to borrowing `encode(into:)`, re-measure, merge only if
the count drops and every gate is green.

**Status (2026-06-25): the encode half is DONE.** `HTTP3Connection.encodeResponseSection` now
borrow-encodes into a reserved buffer (QPACK gained `beginSection(into:)` + a public `encode(_:into:)`),
with a cached status string — **31 → 11 allocations**, pinned by `HTTP3ResponseAllocationTests`. Gate
cleared: full suite + QPACK/h3 conformance + fuzz green, ASan clean (owned buffer, no escape). The same
borrow-encode was then mirrored onto the **HTTP/2** response path (HPACK), 58 → 41 allocations, sharing a
new `HTTPStatus.decimalString` (HTTPCore) — same gate cleared.

**Decode-side (2026-06-25): investigated — near the owned-request floor, no change forced.** The 24-malloc
receive splits into decode 6 (already minimal — `QPACKAllocationTests`), the owned-`HTTPRequest` mapping 17
(`RequestMapperAllocationTests` — its `HTTPFields` + pseudo-header values + struct, all of which *escape*
to the responder), and the 1 eager frame-payload copy. `HTTPFieldName` already reuses an already-lowercase
name, so there is no redundant lowercasing to cut. The remaining levers — the decoder producing
`HTTPFields` directly (to drop the `[HeaderField]` intermediate) and a borrowed frame-payload span — are
risky API / lifetime changes for a modest gain, so per the gate they stay **deferred**. The measure-first
discipline did its job: it stopped a risky change that would not have paid off.

## 2. Inbound `Content-Encoding` decompression

**Finding.** Not implemented — deliberately. It is net-new attack surface (decompression bombs,
CWE-409) with **no current consumer**; the outbound gzip path is already bounded.

**Design (when a consumer needs it).** A bounded, streaming, opt-in decompressor:
- **Absolute cap** (`maxDecompressedSize`) and a **ratio cap** (reject when decompressed/compressed
  exceeds a bound) — the same posture as the outbound gzip-bomb defense.
- **Incremental** (never buffer the whole input or output); fail closed on the cap with `413`.
- **Opt-in** per server/route, **off by default** — a server that does not consume request bodies of a
  declared encoding must not pay the surface.

**Risk.** The decompression-bomb surface itself; mismatched `Content-Length` vs decompressed size.

**Gate.** A real consumer need **plus** a fuzz suite over malformed/bomb inputs **plus** the bounds
enforced and reviewed. **Recommendation: keep deferred** until a consumer needs it — adding surface
without demand fails the project's own "defer net-new surface" bar. This design makes it ready on demand.

**Status (2026-06-25): implemented (opt-in) — gate cleared.** `DecompressionMiddleware` gunzips a
`Content-Encoding: gzip` request body before the responder, off by default. Bomb defense (CWE-409): the
output is capped both absolutely (`HTTPLimits.maxDecompressedBodySize`) and by ratio
(`maxDecompressionRatio`) — `Inflate.gunzip` decodes into a `cap+1` buffer and rejects on overflow, so a
malformed/oversized/over-ratio member fails closed with `413` and a bomb is never buffered. Covered by
`DecompressionMiddlewareTests` (round-trip, the three rejection paths, passthrough) and
`DecompressionFuzzTests` (random + mutated-gzip, never traps); ASan clean. Wired into `httpd-example` to
demonstrate it. Non-gzip encodings (deflate/br) are left untouched for the app; CRC/ISIZE verification is
a possible follow-up (the DEFLATE decode + the size cap are the security-relevant checks).

## 3. HTTP/3 0-RTT early-data policy

**Finding.** Owned by the `m7-http3` sibling worktree (the live QUIC/h3 transport). 0-RTT early data is
replayable (RFC 9001 §9.2), so a non-idempotent request in early data is a replay risk.

**Design.** Safe default first, enhancement second:
- **Default: disable 0-RTT** (`NWProtocolQUIC.Options` early-data knobs) — the conservative posture.
- **Enhancement: if enabled, gate by method** — accept idempotent methods (GET/HEAD) in early data,
  answer a non-idempotent early-data request with **`425 Too Early`** (RFC 8470) so the client retries
  after the handshake completes.

**Risk.** Replay of non-idempotent operations; **coordination** — this touches the sibling's QUIC layer.

**Gate.** Alignment with the `m7-http3` sibling **before any `main` change** (the sibling worktree is
off-limits to this campaign). **Recommendation:** land the default-disable posture as the initial safe
state; schedule the `425`-gating enhancement with the sibling. Do not modify main's QUIC/h3 transport
unilaterally.

**Status (2026-06-25): resolved by investigation — the safe posture already holds, now documented.** With
the `m7-http3` worktree removed this is no longer sibling-gated. Network.framework's QUIC TLS (`QUIC.TLS`)
exposes **no early-data control** to the application — unlike TCP's `Network.TLS.earlyDataEnabled(_:)` —
and neither QUIC backbone enables 0-RTT, so no request is processed from replayable early data, with
nothing to toggle. Both transports now carry the policy comment. The `425 Too Early` (RFC 8470) gate
remains the required defense *if* a future framework API ever enables QUIC 0-RTT — it is not wireable
today (the transport surfaces no early-data flag) and is moot while 0-RTT is off.

## Status of everything else

Done + merged: the comparison matrix (§ perf-battletest), worktree/branch consolidation, the tiered
repo layout (ADR 0003), the two complexity splits, the Router/Range/Metrics wiring + the Router HEAD
fold, the F-EMFILE accept-backoff fix, the CI trap-lint repair + release lane, and now the **h3 response
encode** (item 1, encode half — 31 → 11 allocs). The h3 receive-side borrow, inbound decompression, and
0-RTT early-data remain, each held behind the gate above.
