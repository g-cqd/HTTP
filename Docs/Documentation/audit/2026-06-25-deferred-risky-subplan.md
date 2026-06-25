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

## Status of everything else

Done + merged: the comparison matrix (§ perf-battletest), worktree/branch consolidation, the tiered
repo layout (ADR 0003), the two complexity splits, the Router/Range/Metrics wiring + the Router HEAD
fold, the F-EMFILE accept-backoff fix, and the CI trap-lint repair + release lane. These three items are
the genuine remainder, each held behind the gate above.
