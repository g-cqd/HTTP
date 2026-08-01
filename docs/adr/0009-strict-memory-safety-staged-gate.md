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
