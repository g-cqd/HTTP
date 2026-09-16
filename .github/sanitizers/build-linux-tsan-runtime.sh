#!/usr/bin/env bash
# Build the matching Swift Synchronization runtime with visible atomic operations for TSan.
set -euo pipefail

destination="${1:?usage: build-linux-tsan-runtime.sh DESTINATION}"
source_revision=80702ec6ad4159b69f624ef4a814946b16237379
swift --version | grep -F 'Swift 80702ec6ad4159b)' >/dev/null || {
  echo 'The TSan runtime must match the pinned Swift toolchain.' >&2
  exit 1
}
mkdir -p "$destination"
destination="$(cd "$destination" && pwd)"
sources_directory="$destination/source"
mkdir -p "$sources_directory"

# Fetch immutable upstream sources, including their license and the standard-library generator.
python3 - "$source_revision" "$sources_directory" <<'PY'
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sys
from urllib.request import urlopen

revision, destination = sys.argv[1:]
prefix = "stdlib/public/Synchronization/"
files = [
    "LICENSE.txt", "utils/gyb", "utils/gyb.py", "utils/gyb_stdlib_support.py",
    "utils/SwiftAtomics.py", "utils/availability-macros.def",
] + [prefix + name for name in [
    "Cell.swift", "Mutex/LinuxImpl.swift", "Mutex/Mutex.swift", "Mutex/SpinLoopHint.swift",
    "Atomics/Atomic.swift", "Atomics/AtomicBool.swift", "Atomics/AtomicFloats.swift",
    "Atomics/AtomicLazyReference.swift", "Atomics/AtomicMemoryOrderings.swift",
    "Atomics/AtomicOptional.swift", "Atomics/AtomicPointers.swift",
    "Atomics/AtomicRepresentable.swift", "Atomics/WordPair.swift",
    "Atomics/AtomicIntegers.swift.gyb", "Atomics/AtomicStorage.swift.gyb",
]]

def fetch(name):
    target = Path(destination, name)
    target.parent.mkdir(parents=True, exist_ok=True)
    with urlopen(f"https://raw.githubusercontent.com/swiftlang/swift/{revision}/{name}", timeout=60) as response:
        target.write_bytes(response.read())

with ThreadPoolExecutor(max_workers=4) as pool:
    list(pool.map(fetch, files))
PY

cd "$sources_directory"
for name in AtomicIntegers AtomicStorage; do
  python3 utils/gyb --line-directive '' \
    -o "stdlib/public/Synchronization/Atomics/$name.swift" \
    "stdlib/public/Synchronization/Atomics/$name.swift.gyb"
done

availability=()
while IFS= read -r line; do
  [[ -z "$line" || "$line" == \#* ]] && continue
  availability+=(-define-availability "$line")
done < utils/availability-macros.def

# Match the upstream standard-library flags. Compile each primary file separately because
# TSan SILGen crashes on Mutex's generic inout body. Every Mutex method is alwaysEmitIntoClient
# and transparent, so the test executable instruments those methods at their call sites.
# SpinLoopHint has no memory access; TSan also generates invalid LLVM IR for its CPU hint.
common=(-parse-as-library -module-name Synchronization -O -g -enable-library-evolution
  -library-level api -swift-version 5 -runtime-compatibility-version none
  -enable-builtin-module -enable-experimental-feature RawLayout
  -enable-experimental-feature StaticExclusiveOnly -enable-experimental-feature Extern
  # Swift throws do not use C++ unwinding. LLVM's C++ cleanup insertion turns
  # the x86 clock intrinsic in LinuxImpl into an invalid invoke instruction.
  -Xllvm -tsan-handle-cxx-exceptions=false
  -strict-memory-safety "${availability[@]}")
sources=(stdlib/public/Synchronization/*.swift stdlib/public/Synchronization/Atomics/*.swift
  stdlib/public/Synchronization/Mutex/*.swift)
mkdir -p objects
for primary in "${sources[@]}"; do
  others=()
  for file in "${sources[@]}"; do
    [[ "$file" == "$primary" ]] || others+=("$file")
  done
  sanitizer=()
  if [[ "$primary" != */Mutex.swift && "$primary" != */SpinLoopHint.swift ]]; then
    sanitizer=(-sanitize=thread)
  fi
  swiftc -frontend -c "${common[@]}" "${sanitizer[@]}" \
    -primary-file "$primary" "${others[@]}" -o "objects/$(basename "$primary" .swift).o"
done
swiftc -emit-library -sanitize=thread objects/*.o -o "$destination/libswiftSynchronization.so"

# Preserve every symbol exported by the installed runtime; clients retain its original module.
swift_library_directory="$(swift -print-target-info | python3 -c \
  'import json,sys; print(json.load(sys.stdin)["paths"]["runtimeLibraryPaths"][0])')"
nm -D --defined-only "$swift_library_directory/libswiftSynchronization.so" | awk '{print $3}' | sort > original-symbols
nm -D --defined-only "$destination/libswiftSynchronization.so" | awk '{print $3}' | sort > rebuilt-symbols
comm -23 original-symbols rebuilt-symbols > missing-symbols
if [[ -s missing-symbols ]]; then
  cat missing-symbols >&2
  echo 'The instrumented runtime is missing installed ABI symbols.' >&2
  exit 1
fi
