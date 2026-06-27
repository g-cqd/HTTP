#!/bin/bash
#
#  vendor-boringssl.sh — (re)generate the vendored, symbol-prefixed BoringSSL under
#  Sources/Core/CHTTPBoringSSL (ADR 0004, Phase 6).
#
#  Strategy (see Sources/Core/CHTTPBoringSSL/NOTICE.txt): BoringSSL ships no SwiftPM packaging, and
#  generating the flattened/prefixed/asm tree from upstream is revision-fragile (the prefix tooling has
#  moved between BoringSSL revisions). We therefore take apple/swift-nio-ssl's already-generated,
#  proven CNIOBoringSSL tree (Apache-2.0 vendoring of BoringSSL, ISC/OpenSSL-licensed) and deterministically
#  re-namespace it CNIOBoringSSL -> CHTTPBoringSSL. swift-nio-ssl is NOT a build- or run-time dependency of
#  this package — only BoringSSL is vendored here. To bump BoringSSL, re-run this against a newer
#  swift-nio-ssl ref. Re-running clobbers Sources/Core/CHTTPBoringSSL wholesale (the hand-written shim lives
#  in the separate Sources/Core/CHTTPBoringSSLShims target and is untouched).
#
#  Usage:   scripts/vendor-boringssl.sh [swift-nio-ssl-ref]
#  Example: scripts/vendor-boringssl.sh 2.31.0          # a tag, branch, or commit (default: main)
#
set -euo pipefail

REF="${1:-main}"
REPO="https://github.com/apple/swift-nio-ssl.git"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
DST="$HERE/Sources/Core/CHTTPBoringSSL"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "==> cloning swift-nio-ssl@${REF}"
git clone --depth 1 --branch "$REF" "$REPO" "$TMP/nio-ssl" 2>/dev/null \
  || git clone "$REPO" "$TMP/nio-ssl"  # fall back to full clone if REF is a bare commit
if [ "$REF" != "main" ]; then (cd "$TMP/nio-ssl" && git checkout --quiet "$REF" 2>/dev/null || true); fi
SRC="$TMP/nio-ssl/Sources/CNIOBoringSSL"
NIO_REV="$(cd "$TMP/nio-ssl" && git rev-parse HEAD)"
BORINGSSL_LINE="$(cat "$SRC/hash.txt")"

echo "==> staging + re-namespacing CNIOBoringSSL -> CHTTPBoringSSL"
rm -rf "$DST"
mkdir -p "$DST"
cp -R "$SRC/" "$DST/"

# 1. file CONTENTS
find "$DST" -type f \( -name '*.h' -o -name '*.cc' -o -name '*.c' -o -name '*.S' \
    -o -name '*.inc' -o -name '*.modulemap' -o -name '*.txt' \) -print0 \
  | xargs -0 perl -pi -e 's/CNIOBoringSSL/CHTTPBoringSSL/g; s/C_NIO_BORINGSSL/C_HTTP_BORINGSSL/g'

# 2. file NAMES (deepest-first)
find "$DST" -depth -name 'CNIOBoringSSL*' -print0 | while IFS= read -r -d '' f; do
  d=$(dirname "$f"); b=$(basename "$f"); mv "$f" "$d/${b/CNIOBoringSSL/CHTTPBoringSSL}"
done

# 3. umbrella header (our own attribution; same #include list)
UMB="$DST/include/CHTTPBoringSSL.h"
INCLUDES="$(grep -E '^#include "(experimental/)?CHTTPBoringSSL_' "$UMB")"
cat > "$UMB" <<HEADER
//
//  CHTTPBoringSSL.h — vendored BoringSSL umbrella header
//
//  This module is a vendored, symbol-prefixed (CHTTPBoringSSL_*) copy of BoringSSL, providing the
//  libssl/libcrypto surface the portable TLS backbone needs (ADR 0004, Phase 6) with no system-OpenSSL
//  dependency. The C sources under crypto/, ssl/, gen/, third_party/ are BoringSSL (see LICENSE in each).
//  The vendoring layout + symbol-prefixing derive from swift-nio-ssl's process (Apache-2.0) — see NOTICE.txt
//  and hash.txt for the exact upstream revision. Do not edit by hand; re-run scripts/vendor-boringssl.sh.
//
#ifndef C_HTTP_BORINGSSL_H
#define C_HTTP_BORINGSSL_H

$INCLUDES

#endif  // C_HTTP_BORINGSSL_H
HEADER

# 4. modulemap
cat > "$DST/include/module.modulemap" <<'MAP'
module CHTTPBoringSSL {
    umbrella header "CHTTPBoringSSL.h"
    export *
}
MAP

# 5. NOTICE + hash
cat > "$DST/NOTICE.txt" <<'NOTICE'
This directory contains a vendored, symbol-prefixed copy of BoringSSL.

BoringSSL
  Source: https://boringssl.googlesource.com/boringssl
  Revision: see hash.txt
  License: ISC / OpenSSL / SSLeay (see the per-file headers under crypto/, ssl/, third_party/).

Vendoring process
  The SwiftPM-friendly layout (flattened sources, renamed CHTTPBoringSSL_* headers, the generated
  CHTTPBoringSSL_boringssl_prefix_symbols*.h symbol-prefix headers, per-architecture assembly, and the
  executable-stack guards) derives from the Apache-2.0 licensed vendoring process of
  apple/swift-nio-ssl (https://github.com/apple/swift-nio-ssl), re-namespaced from CNIOBoringSSL to
  CHTTPBoringSSL by scripts/vendor-boringssl.sh. swift-nio-ssl is NOT a build- or run-time dependency
  of this package; only BoringSSL itself is vendored here.
NOTICE
{
  echo "$BORINGSSL_LINE"
  echo "Re-namespaced from apple/swift-nio-ssl@${NIO_REV} by scripts/vendor-boringssl.sh."
} > "$DST/hash.txt"

echo "==> verifying no stray CNIOBoringSSL references"
if grep -rIl "CNIOBoringSSL" "$DST" | grep -v "NOTICE.txt"; then
  echo "!! stray CNIOBoringSSL references (above)"; exit 1
fi
echo "==> done. $(find "$DST" -type f | wc -l | tr -d ' ') files; ${BORINGSSL_LINE}"
