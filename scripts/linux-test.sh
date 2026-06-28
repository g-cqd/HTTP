#!/bin/bash
#
#  linux-test.sh — build/test the package on Linux from macOS via Apple's `container` runtime.
#
#  The library's transport floor is platform-specific (kqueue/Network on Darwin, epoll on Linux), so the
#  Linux build path can only be verified on a Linux toolchain. This wraps the recipe the 2026-06-28
#  Linux-readiness audit established: an ephemeral `swiftlang/swift:nightly-noble` container with the repo
#  bind-mounted at /work, a *separate* Linux scratch (.build-linux) so the macOS .build is never clobbered,
#  and dependencies seeded offline from the macOS-resolved .build/checkouts (the lightweight VM's NAT blocks
#  git clone to github:443 — verified, so on-line resolution is not an option).
#
#  Requirements: Apple `container` (https://github.com/apple/container) running (`container system start`),
#  the image pulled (`container image pull docker.io/swiftlang/swift:nightly-noble`), and a macOS-resolved
#  .build/checkouts to seed from (run any `swift build` on the host first).
#
#  Usage:
#    scripts/linux-test.sh                       # swift test (full suite)
#    scripts/linux-test.sh build                 # swift build (library + products)
#    scripts/linux-test.sh test --filter Foo     # any swift subcommand + args
#    HTTP_PORTABLE_TLS=1 scripts/linux-test.sh    # opt-in feature legs are forwarded
#
#  Env knobs: HTTP_LINUX_IMAGE, HTTP_LINUX_SCRATCH, HTTP_LINUX_MEM (default 8g), HTTP_LINUX_CPUS,
#  HTTP_LINUX_SEED_SRC (default <repo>/.build), and the package feature flags (HTTP_PORTABLE_TLS,
#  HTTP_ZSTD, HTTP_BROTLI, HTTP_WARNINGS_AS_ERRORS, HTTP_OPENSSL_PREFIX, HTTP_BROTLI_PREFIX).
#
set -euo pipefail

IMAGE="${HTTP_LINUX_IMAGE:-docker.io/swiftlang/swift:nightly-noble}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
SCRATCH="${HTTP_LINUX_SCRATCH:-$REPO/.build-linux}"
SEED_SRC="${HTTP_LINUX_SEED_SRC:-$REPO/.build}"
MEM="${HTTP_LINUX_MEM:-8g}"
CPUS="${HTTP_LINUX_CPUS:-}"

# Default action is `test`; everything after the script name is passed verbatim to `swift`.
if [ "$#" -eq 0 ]; then set -- test; fi

mkdir -p "$SCRATCH"

# --- Offline dependency seed -------------------------------------------------------------------------
# Copy the macOS-resolved checkouts + bare repositories into the Linux scratch (both are
# platform-independent git data; compiled products are NOT copied). Reseed only when Package.resolved
# changes, tracked by a hash sentinel — the copy is a couple of seconds but pointless every run.
seed() {
  if [ ! -d "$SEED_SRC/checkouts" ]; then
    echo "!! no seed source at $SEED_SRC/checkouts — run a host 'swift build' first (the container VM cannot git clone)." >&2
    exit 1
  fi
  echo "==> seeding offline dependencies from $SEED_SRC"
  rm -rf "$SCRATCH/checkouts" "$SCRATCH/repositories"
  cp -R "$SEED_SRC/checkouts" "$SCRATCH/checkouts"
  cp -R "$SEED_SRC/repositories" "$SCRATCH/repositories" 2>/dev/null || true
  [ -f "$SEED_SRC/workspace-state.json" ] && cp "$SEED_SRC/workspace-state.json" "$SCRATCH/workspace-state.json"
}
RESOLVED="$REPO/Package.resolved"
SENTINEL="$SCRATCH/.seed-hash"
want_hash="none"
[ -f "$RESOLVED" ] && want_hash="$(shasum -a 256 "$RESOLVED" | awk '{print $1}')"
if [ ! -d "$SCRATCH/repositories" ] || [ "${want_hash}" != "$(cat "$SENTINEL" 2>/dev/null || echo missing)" ]; then
  seed
  echo "$want_hash" > "$SENTINEL"
fi

# --- Feature-flag passthrough ------------------------------------------------------------------------
ENVARGS=()
for v in HTTP_PORTABLE_TLS HTTP_ZSTD HTTP_BROTLI HTTP_WARNINGS_AS_ERRORS HTTP_OPENSSL_PREFIX HTTP_BROTLI_PREFIX; do
  if [ -n "${!v:-}" ]; then ENVARGS+=(--env "$v=${!v}"); fi
done
CPUARG=()
if [ -n "$CPUS" ]; then CPUARG=(--cpus "$CPUS"); fi

# Inside the container: resolve offline from the seeded repositories first (--skip-update never touches the
# network), then run the requested swift subcommand with --disable-automatic-resolution so the build/test
# step itself can't stall on a blocked git fetch. SwiftPM flags are injected right after the subcommand so
# `run <exe> <args>` still routes <args> to the executable.
# shellcheck disable=SC2016  # $sub/$@ must expand inside the container's shell, not this one.
REMOTE_SCRIPT='
  git config --global --add safe.directory /work >/dev/null 2>&1 || true
  swift package resolve --scratch-path /lbuild --skip-update
  sub="$1"; shift
  exec swift "$sub" --scratch-path /lbuild --disable-automatic-resolution "$@"
'

echo "==> container run: swift $* (image=$IMAGE, scratch=$SCRATCH, mem=$MEM)"
# Note the ${ARR[@]+"${ARR[@]}"} idiom: macOS still ships bash 3.2, where an empty array expanded as
# "${ARR[@]}" trips `set -u` ("unbound variable"). This form expands to nothing when the array is empty.
exec container run --rm \
  --memory "$MEM" \
  ${CPUARG[@]+"${CPUARG[@]}"} \
  --volume "$REPO:/work" \
  --volume "$SCRATCH:/lbuild" \
  --workdir /work \
  ${ENVARGS[@]+"${ENVARGS[@]}"} \
  "$IMAGE" \
  bash -lc "$REMOTE_SCRIPT" _ "$@"
