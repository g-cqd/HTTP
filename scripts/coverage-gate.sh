#!/usr/bin/env bash
#
# scripts/coverage-gate.sh [THRESHOLD] — Sources line coverage of the last `swift test --enable-code-coverage` (macOS).
# CI runs it after the macOS debug tests, which swift-ci builds with coverage (`.ci/action.json`, command
# `coverage-gate`). SwiftPM emits a per-target .xctest bundle, so a single-binary llvm-cov export under-reports the
# modules that bundle does not link; exporting the merged profile across every bundle gives the true Sources line
# coverage. The threshold is a floor against a module losing its tests, with headroom for normal churn; raise it as
# coverage grows.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
threshold="${1:-85}"
build="${SCRATCH:-.build}"

prof="$(find -L "$build" -name default.profdata -path '*/debug/*' | head -1)"
[ -n "$prof" ] || { echo "::error::no coverage profile under $build: run the tests with --enable-code-coverage first"; exit 1; }
bins=()
while IFS= read -r bundle; do bins+=("$bundle/Contents/MacOS/$(basename "$bundle" .xctest)"); done \
    < <(find -L "$build" -path '*/debug/*' -name '*.xctest' -type d)
[ "${#bins[@]}" -gt 0 ] || { echo "::error::no test bundles under $build"; exit 1; }
objects=("${bins[0]}")
for bundle in "${bins[@]:1}"; do objects+=(-object "$bundle"); done
report="$(mktemp)"
trap 'rm -f "$report"' EXIT
xcrun llvm-cov export -format=text -summary-only -instr-profile="$prof" \
    -ignore-filename-regex="Tests/|[.]build/|Benchmarking/|checkouts/" "${objects[@]}" > "$report"
python3 - "$report" "$threshold" <<'PY'
import json, sys
percent = json.load(open(sys.argv[1]))["data"][0]["totals"]["lines"]["percent"]
threshold = float(sys.argv[2])
print(f"Sources line coverage: {percent:.2f}% (floor {threshold:g}%)")
if percent < threshold:
    print(f"::error::Sources line coverage is below the {threshold:g}% floor")
    sys.exit(1)
PY
