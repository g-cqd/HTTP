#!/usr/bin/env bash
# Exercise both synchronization and race detection before using the runtime in the full suite.
set -euo pipefail
runtime="${1:?usage: check-linux-tsan-runtime.sh RUNTIME_DIRECTORY}"
fixtures="$(cd "$(dirname "$0")" && pwd)"
runtime="$(cd "$runtime" && pwd)"
library_directory="$(swift -print-target-info | python3 -c \
  'import json,sys; print(json.load(sys.stdin)["paths"]["runtimeLibraryPaths"][0])')"
for mode in locked unlocked; do
  swiftc -parse-as-library -swift-version 6 -sanitize=thread -no-toolchain-stdlib-rpath \
    -Xlinker -export-dynamic -Xlinker -rpath -Xlinker "$runtime:$library_directory" \
    "$fixtures/tsan-$mode.swift" -o "$runtime/$mode"
done
ldd "$runtime/locked" | grep -F "$runtime/libswiftSynchronization.so"
"$runtime/locked"
status=0
"$runtime/unlocked" > "$runtime/unlocked.log" 2>&1 || status=$?
if [[ "$status" != 66 ]] || ! grep -q 'ThreadSanitizer:.*race' "$runtime/unlocked.log"; then
  cat "$runtime/unlocked.log" >&2
  echo 'TSan did not reject the deliberate unlocked race.' >&2
  exit 1
fi
echo 'Locked counter passed; deliberate unlocked race was detected.'
