# ADR 0009 — Strict memory safety (SE-0458): a staged gate, not an all-or-nothing flip

- **Status:** Accepted
- **Context date:** 2026-07-31
- **Supersedes** ADR 0002 (strict memory safety — adopt incrementally, not yet globally). ADR 0002's
  *decision* stands; what it lacked was enforcement, and that is what this ADR adds.

## Context

ADR 0002 measured strict memory safety on `HTTPCore`, found "dozens of annotations spread across the
whole package", and deferred adoption until the M5/M6 churn settled. It wrote down a plan and no gate.

A plan without a gate ratchets the wrong way. Between ADR 0002 and today the package grew ~100
commits of remediation; nothing stopped any of them from adding unsafe sites, and nothing told us
whether the number was going up or down. "Adopt incrementally" with no counter is indistinguishable
from "do not adopt".

## Measurement

Full census on this toolchain (Apple Swift 6.4, `swiftlang-6.4.0.27.1`, arm64 macOS), via
`swift build -Xswiftc -strict-memory-safety` over every product, deduplicated by (file, line, column):

| target            | sites |
| ----------------- | ----: |
| HTTPTransport     |   149 |
| HTTPServer        |    79 |
| HTTPCore          |    77 |
| HTTPTestSupport   |    75 |
| WebSocket         |    29 |
| HTTP1             |    23 |
| HTTP2             |    21 |
| HTTP3             |     8 |
| httpd-example     |     4 |
| **HTTPConcurrency** | **0** |
| **HPACK**         | **0** |
| **QPACK**         | **0** |
| **HTTPObservability** | **0** |
| **HTTPAuth**      | **0** |

**465 sites in 9 targets.** By diagnostic kind: 455 `expression uses unsafe constructs but is not
marked with 'unsafe'`, 6 `for-in loop uses unsafe constructs…`, and 12 `has storage involving unsafe
types` (4 struct, 4 class, 2 generic struct, 2 generic class).

The 465 are the substrate ADR 0002 predicted: `withUnsafeBytes` at every span→`String`/`[UInt8]`
materialization boundary, `unsafeLoad`/`loadUnaligned` in the decoders, `UnsafeMutableRawBufferPointer`
and imported C pointer APIs across the transport backbones, `Atomic`/`Mutex` storage, and
`clock_gettime`-shaped syscalls.

`HTTPObservability` and `HTTPAuth` were already at zero — they are bridge and middleware code with no
byte plumbing. `HTTPConcurrency` (1), `HPACK` (2) and `QPACK` (2) were brought to zero for this ADR:
five `unsafe` markers, each carrying its safety argument in a comment beside it.

## Decision

**Enforce strict memory safety per target on the targets that are at zero; hold the rest with a
counted budget that may fall but never rise.**

Two mechanisms, deliberately different in strength:

1. **Hard gate (compiler).** `strictMemorySafeTargets` in `Package.swift` adds
   `.strictMemorySafety()` to `HTTPConcurrency`, `HPACK`, `QPACK`, `HTTPObservability` and `HTTPAuth`.
   Combined with `HTTP_WARNINGS_AS_ERRORS`, the first un-annotated unsafe expression added to one of
   those targets is a **build error** in `build-test` and `release-test` — not a warning in a log.
2. **Ratchet (counted).** `scripts/strict-memory-safety.py` re-runs the census and compares each
   remaining target against `.github/strict-memory-safety-budget.tsv`. Over budget fails; under budget
   passes and emits a notice to tighten. The `strict-memory-safety` CI job runs it.

A target reaches zero, moves from the budget file into `strictMemorySafeTargets`, and stops being a
number. That one-line promotion is the unit of progress this ADR exists to make cheap.

### Why the gate is not applied bottom-up

ADR 0002's plan orders adoption `HTTPCore` → `HTTP1`/`HPACK` → `HTTP2` → `HTTPTransport` →
`HTTPServer` — lowest first, because annotating a lower module behind `@safe` wrappers shrinks the
count in the modules above it. That ordering is still the right way to do the *work*.

It is not the right way to place the *gate*. `HTTPObservability` and `HTTPAuth` sit at the top of the
graph and are at zero today; gating them costs nothing and protects them immediately. Waiting for
`HTTPCore` before protecting anything would leave five clean targets unguarded for the duration.
Gate where it is free; work bottom-up where it is not.

### Why a ratchet rather than a deadline

465 annotations is a multi-week sweep that has to be interleaved with in-flight work — exactly ADR
0002's objection, which has not expired. A ratchet converts an unbounded backlog into a monotone one:
the number cannot get worse while the sweep proceeds, and every reduction is banked by a commit that
lowers the budget. That is a weaker promise than a deadline and a much stronger one than a plan.

### Cost

The `strict-memory-safety` job is a full `-strict-memory-safety` build of every product, roughly the
cost of `build-test` minus the test run. It is its own job so it neither slows nor is masked by the
main lane.

## Consequences

- Five targets can no longer regress; nine are bounded and can only improve.
- A contributor adding an unsafe expression to `HPACK` gets a compile error with the SE-0458
  diagnostic and its documentation link — the annotation is *where* the safety argument must be
  written, which is the real value of SE-0458 and the reason ADR 0002 wanted it.
- The budget file is a public backlog: `HTTPTransport` at 149 is the largest single piece of
  unaudited pointer work in the package, and it is now written down where CI reads it.

## Addendum (2026-08-02): the suppression column

The ratchet as decided above counted un-annotated unsafe expressions — which made *suppression* read
as improvement. Writing `unsafe` in front of an expression stops the compiler asking; `@unchecked
Sendable`, `nonisolated(unsafe)`, `@unsafe`, `unsafeBitCast` and `unsafeDowncast` mean it never asked
at all. Every one of those moved the number down. So suppressions are censused as a second counted
category (`7215af7`): `.github/strict-memory-safety-suppressions.tsv` inventories what is in the
tree, per file and kind, and that inventory is the review record. The column is held at **exact
equality** rather than "may fall" — unspent headroom in a suppression budget is a suppression a later
change can add back unnoticed. Any suppression beyond the inventoried count must carry a
`// SAFETY:` justification on its own line or within the five lines above it; existing entries are
grandfathered because they were argued in prose where they were written.

## Known blind spots — what the numbers do not prove

Stated here so the ratchet lives next to its limits and is not trusted past them. A green
`strict-memory-safety` job proves the *counts* did not rise. It does not prove any of the following,
and the enforcing script (`scripts/strict-memory-safety.py`, "WHAT THIS DOES NOT CATCH") carries the
same list beside the code:

- **A justification that is present but wrong.** `// SAFETY:` is checked for existence and
  placement, never for truth. The gate buys a deliberate act and a greppable marker for review —
  not a proof. No reviewer beyond the person re-baselining ever has to look.
- **Moving unsafe code out of `Sources/` entirely** — into a C shim target, a dependency, or a test
  target. Both censuses stop at this repository's `Sources/`, so the total falls and reads as
  progress while the unsafety merely changed jurisdiction.
- **Transfers between targets with slack.** The first column's per-target ceiling catches a rise,
  not a move: a site migrating from a target under budget into another target under budget changes
  neither verdict. Only the first column tolerates slack at all.
- **Coarsening** — the most likely *accidental* regression. One `unsafe` marker can span a whole
  expression, so merging three marked sub-expressions into one statement lowers the count without
  lowering the unsafety. The compiler reports expressions; the script can only count what the
  compiler reports.
- **Silencers not on the allowlist.** The `SUPPRESSIONS` table names known constructs; `@_spi`,
  `@_silgen_name`, `withMemoryRebound` and friends, and anything the language adds after the list
  was written are invisible to it. The list is an allowlist of known silencers, not a definition of
  "unsafe".
- **Removing `.strictMemorySafety()` from a target in `Package.swift`** — caught, but by the build
  gate rather than the ratchet: the script passes `-strict-memory-safety` to every target itself,
  so the census is independent of the manifest's settings.

The consequence for review practice: a change that touches unsafe code is reviewed on its own
merits; the ratchet only guarantees the reviewer is *told* (a budget or inventory diff line) — and
only when the change crosses one of the counted lines above.

## Plan (unchanged in spirit from ADR 0002, now with a counter)

1. `HTTP3` (8) and `httpd-example` (4) are the next promotions — small enough to annotate in one pass.
2. `HTTPCore` (77) is the leverage: `ByteReader`, `Huffman`, `Base64`, `HTTPDate` and `FieldValidation`
   account for most of it, and hoisting the bounds-checked accessors behind `@safe` wrappers there is
   what will reduce `HTTP1`/`HTTP2`/`WebSocket` without touching them.
3. `HTTPTransport` (149) last, per ADR 0002: it is the genuine unsafe boundary (raw sockets, kqueue/
   epoll event arrays, C interop), and its annotations are documentation of real invariants, not
   ceremony.
4. The package is fully adopted when the budget file is empty and `.strictMemorySafety()` moves into
   the shared `strictSwiftSettings`.
