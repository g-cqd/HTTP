# CI

`.github/workflows/ci.yml` calls the family's pinned swift-ci workflow (`Checks`), configured by `action.json`; every
other job in it is this package's own (strict-memory-safety budget, the scoped macOS and Linux sanitizers, optional
features, the Brotli/zstd codings, benchmarks, h2spec, Autobahn, HTTP/3 conformance, h3 load, soak) and runs after it.
`.ci/swift-ci local` runs the same checks as `Checks` here.

`Checks` runs quality (swift-format and SwiftLint, strict; deadwood, dolly and arcleak against `baselines/`), the macOS
debug tests with coverage, then `scripts/ci-gates.sh` (no SwiftNIO, the shared Aemi pin, a trap-free request path,
RFC citations) and `scripts/coverage-gate.sh 85`, the macOS release tests, and the Linux debug and release tests, all
with `HTTP_WARNINGS_AS_ERRORS=1` and `--no-parallel`. swift-ci's own sanitizer checks are off: the sanitizer jobs in
`ci.yml` carry the package's scoping (UBSan's native build system and filters, the instrumented TSan runtime on Linux,
the LSan suppressions).

`swift.testSkips` skips `AcceptBackpressureTests` in debug: its Network.framework case waits on a fixed deadline that
an instrumented build misses on hosted runners; the release tests run it.

`baselines/` accepts the findings that predate this configuration (deadwood 4, dolly 1330, of which 283 warnings);
only a new one fails.
