# 2026-07-31 repository reconciliation

The canonical checkout is `/Users/gc/Developer/ongoing/swift/HTTP`.

## Reconciled state

- `main` was already clean and byte-identical to the tracked tree in the old
  `g-cqd/HTTP` checkout at `91a60e4cae112c7bef2da53f3457ca314fe705b8`.
- Imported `campaign/battletest` at
  `730af3aa0464acd6596efc13556fa924d36367a3`. This branch is already an
  ancestor of `main`.
- Imported the intentionally unmerged `wip/deep-audit-stripback` at
  `a0a9efead2f2970aff63b6e4f74f4ae785e2afbe`.
- Preserved all 30 static-analysis reports under
  `docs/audit/tool-reports/2026-07-31/`.
- Restored 130 benchmark result/config/log artifacts under
  `Benchmarking/Bench/results/` and `Benchmarking/Django/results/`.

The ordered per-file SHA-256 aggregate for the copied reports is
`15cbeb0e2dfc1392ca1e52960bdc2719f4f81a21d93da9058392ded02f7e2974`.
The corresponding aggregate for the restored benchmark artifacts is
`64f1ffbffa69c8b58fa317439edf82d0a180127c10509672ce99d2fc6f70916b`.

## Deliberate exclusions

The following machine-local or reproducible state was not migrated:

- SwiftPM build caches and workspace/user state (`.build/`, `.swiftpm/`)
- editor and agent-local state (`.vscode/`, `.claude/`)
- Python virtual environments and bytecode caches
- `.DS_Store` files and the ignored `Package.resolved`
- the recovered `Benchmarking/Bench/results/go-bench` executable; its source
  and benchmark output were preserved

The old checkout's unreachable Git objects were not promoted to refs. They
were abandoned intermediate history rather than named repository state; all
named local branches were imported.
