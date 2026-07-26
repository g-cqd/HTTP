# ADR 0002 — Strict memory safety (SE-0458): adopt incrementally, not yet globally

- **Status:** Accepted (deferred adoption)
- **Context date:** 2026-06

## Context

CLAUDE.md lists "strict memory" as a goal. Swift 6.2's opt-in **strict memory safety**
(SE-0458) is the canonical enforcement: the compiler flags any expression that "uses unsafe
constructs but is not marked with `unsafe`", and each such site must be acknowledged with the
`unsafe` keyword (or a type marked `@safe`/`@unsafe`).

It is enabled per target with the `.strictMemorySafety()` `SwiftSetting`, or globally with the
`-strict-memory-safety` frontend flag.

## Measurement

Probed with `swift build --target HTTPCore -Xswiftc -strict-memory-safety`. It works and flags the
expected substrate sites, e.g. in `ByteReader`:

- `init(_ buffer: UnsafeRawBufferPointer)` — parameter of unsafe type
- `bytes.unsafeLoad(fromByteOffset:as:)` — every zero-copy read
- `slice(in:).withUnsafeBytes { String(decoding: $0, …) }` — the materialization boundary

The same classes of site recur across **every** target: `withUnsafeBytes` in the parsers (HTTP1,
HPACK, HTTP2), `unsafeLoad`/`loadUnaligned` in the decoders, and the raw `UnsafeMutableRawBufferPointer`
/ `Atomic` / pointer arithmetic in `HTTPTransport`. Adoption is dozens of annotations spread across
the whole package.

## Decision

**Adopt incrementally, bottom-up, once the M5/M6 churn settles — do not flip it on globally now.**

Rationale:

1. Under our CI's warnings-as-errors, enabling it globally turns every un-annotated unsafe site into
   a build error, so the package would not compile until *all* targets are annotated in one sweep.
2. HTTP/2, the new concurrency/test-support modules, and the server runtime are under active
   development; a repo-wide `unsafe`-annotation pass now would churn against in-flight work and is
   best done when each module is stable.

## Plan

1. Adopt per target, lowest first: `HTTPCore` → `HTTP1`/`HPACK` → `HTTP2` → `HTTPTransport` →
   `HTTPServer`. Add `.strictMemorySafety()` to that target's `swiftSettings` (set on the target
   *before* the manifest's strict-settings loop so it is preserved).
2. In each target, annotate every flagged site with `unsafe` (or hoist genuinely-checked accesses
   behind a `@safe` wrapper where the invariant is local — e.g. `ByteReader`'s bounds-checked
   `loadByte`). The annotations are documentation: they mark exactly where the spatial/temporal
   safety argument lives.
3. The package is fully adopted when `-strict-memory-safety` is in the shared `strictSwiftSettings`
   and CI is green under warnings-as-errors.
