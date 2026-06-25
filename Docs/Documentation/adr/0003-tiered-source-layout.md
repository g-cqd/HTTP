# ADR 0003 — Tiered source layout (Core / Protocols / Transport / Server / Testing / Examples)

- **Status:** Accepted
- **Context date:** 2026-06

## Context

The package had grown to **14 flat module directories** under `Sources/` (plus 11 mirrored test
targets) and **six sibling content folders** at the repo root (`Sources`, `Tests`, `Documentation`,
`Standards`, `Bench`, `Benchmarks`). "Too many folders on one level" had become real navigation
friction: the flat `Sources/` listing interleaved the foundation layer, the protocol engines, header
compression, the I/O transport, the server runtime, test support, two C shims, and the example with
no grouping or ordering cue.

## Decision

Group the modules into conceptual tiers by **directory only**, and collapse the doc/measurement
folders into two coherent groups — **without renaming any module**, so every `import` is unchanged:

    Sources/Core        HTTPCore, HTTPConcurrency, CCRC32, CHTTPTestMalloc
    Sources/Protocols   HTTP1, HTTP2, HTTP3, HPACK, QPACK, WebSocket
    Sources/Transport   HTTPTransport
    Sources/Server      HTTPServer
    Sources/Testing     HTTPTestSupport
    Sources/Examples    httpd-example
    Tests/              mirrors the same tiers
    Docs/               Documentation, Standards
    Benchmarking/       Bench (load harness), Benchmarks (ordo package)

Each target declares an explicit `path:` in `Package.swift`; the module name remains the directory
leaf, so the SwiftPM product/target names — and therefore all imports across the package and for
downstream consumers — are byte-for-byte identical to before.

## Rationale

1. **Navigability without renames.** Module names are load-bearing (every `import`, every product
   name, every downstream dependency edge). Moving *directories* and adding `path:` keeps the change
   behavior-free while cutting the root from 14 sibling dirs to 4 and giving `Sources/` a legible tier
   order (foundation → protocols → transport → server → testing → examples).
2. **Coherence over a literal single `Docs/`.** A SwiftPM benchmark *package* and shell load-test
   *scripts* are not documentation, so `Benchmarking/` holds the measurement tooling and `Docs/` holds
   prose + the RFC corpus. Same root reduction as folding all four under `Docs/`, with clearer intent
   ("make it make sense").
3. **The transport backbones already proved the pattern** (`HTTPTransport/{Abstraction,Network,
   POSIXKqueue,POSIXDispatch,SwiftSystem,Fake,Quic}`); this extends the same idea one level up.

## Consequences

- `Package.swift` carries one `path:` per target (25 entries); the **dependency graph is unchanged**.
- Path-bearing tooling was repointed and verified: the `Benchmarks` package's `path: "../.."`
  main-package dependency, `Benchmarking/Bench/run.sh`'s `REPO_ROOT` derivation, the CI
  `--package-path Benchmarking/Benchmarks` invocation, the coverage-ignore regex, the **`trap-lint`
  module list** (a flat-path list that would otherwise silently match nothing), and the living-doc
  source-path references (`Docs/Standards/README.md`, `Docs/Documentation/Security.md`).
- Dated audit documents keep their original flat paths — they are point-in-time snapshots describing
  the layout as it was on their date.
- `git mv` preserved history; `git log --follow <path>` traces a file across the move.
