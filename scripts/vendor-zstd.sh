#!/bin/bash
#
#  vendor-zstd.sh — (re)generate the vendored Zstandard library under Sources/Core/CHTTPZstd/vendor.
#
#  Downloads the upstream release tarball, verifies it against the pinned SHA-256 (the value upstream publishes as
#  `zstd-<version>.tar.gz.sha256`), generates the single-file library with upstream's own amalgamation script
#  (`build/single_file_libs`: compressor and decompressor, no legacy formats, no assembly), and copies it with the
#  public headers and the license. The shim (`chttpzstd.c`, `include/CHTTPZstd.h`) is hand-written and untouched.
#
#  Usage:   scripts/vendor-zstd.sh [version sha256]
#  Example: scripts/vendor-zstd.sh 1.5.7 eb33e51f49a15e023950cd7825ca74a4a2b43db8354825ac24fc1b7ee09e6fa3
#
set -euo pipefail

VERSION="${1:-1.5.7}"
SHA256="${2:-eb33e51f49a15e023950cd7825ca74a4a2b43db8354825ac24fc1b7ee09e6fa3}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
DST="$HERE/Sources/Core/CHTTPZstd/vendor"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

TARBALL="zstd-$VERSION.tar.gz"
echo "==> downloading $TARBALL"
curl -fsSL -o "$TMP/$TARBALL" "https://github.com/facebook/zstd/releases/download/v$VERSION/$TARBALL"

echo "==> verifying SHA-256"
actual="$(shasum -a 256 "$TMP/$TARBALL" | cut -d' ' -f1)"
if [ "$actual" != "$SHA256" ]; then
    echo "::error::SHA-256 mismatch for $TARBALL: expected $SHA256, got $actual" >&2
    exit 1
fi

echo "==> generating the single-file library"
tar -xzf "$TMP/$TARBALL" -C "$TMP"
SRC="$TMP/zstd-$VERSION"
# Single-threaded: upstream's template enables ZSTD_MULTITHREAD (a pthread worker pool) for every non-Emscripten
# build. The server codes each response on its own task; libzstd's workers would add threads outside the server's
# concurrency limits and a pthread link dependency on Linux. One line of the template is switched off, checked.
TEMPLATE="$SRC/build/single_file_libs/zstd-in.c"
grep -q '^#define ZSTD_MULTITHREAD$' "$TEMPLATE" || { echo "::error::zstd-in.c no longer defines ZSTD_MULTITHREAD as expected" >&2; exit 1; }
sed 's|^#define ZSTD_MULTITHREAD$|/* #define ZSTD_MULTITHREAD — disabled by scripts/vendor-zstd.sh: single-threaded */|' \
    "$TEMPLATE" > "$SRC/build/single_file_libs/zstd-in-st.c"
(cd "$SRC/build/single_file_libs" && python3 combine.py -r ../../lib -x legacy/zstd_legacy.h -o zstd.c zstd-in-st.c >/dev/null)
if grep -q '^#define ZSTD_MULTITHREAD' "$SRC/build/single_file_libs/zstd.c"; then
    echo "::error::the generated zstd.c still enables ZSTD_MULTITHREAD" >&2
    exit 1
fi

echo "==> staging into $DST"
rm -rf "$DST"
mkdir -p "$DST"
cp "$SRC/build/single_file_libs/zstd.c" "$DST/zstd.c"
cp "$SRC/lib/zstd.h" "$SRC/lib/zstd_errors.h" "$DST/"
cp "$SRC/LICENSE" "$DST/LICENSE"
cat > "$DST/VENDORED.md" <<EOF
# Vendored Zstandard

- Upstream: https://github.com/facebook/zstd, release \`v$VERSION\`
- Tarball: \`$TARBALL\`, SHA-256 \`$SHA256\` (verified against the pinned value)
- \`zstd.c\`: generated with \`build/single_file_libs/combine.py -r ../../lib -x legacy/zstd_legacy.h\` from upstream's
  \`zstd-in.c\` template with its \`#define ZSTD_MULTITHREAD\` line commented out (single-threaded: no worker pool, no
  pthread dependency) — compressor, decompressor and dictionary builder; no legacy formats; no assembly
  (\`ZSTD_DISABLE_ASM\`)
- \`zstd.h\`, \`zstd_errors.h\`: copied verbatim from \`lib/\`
- License: BSD (\`LICENSE\`), selected from upstream's BSD-or-GPLv2 dual license

Regenerate with \`scripts/vendor-zstd.sh <version> <sha256>\`; never edit these files by hand. The shim
(\`../chttpzstd.c\`) compiles \`zstd.c\` with every libzstd symbol hidden, so this copy can share a process with any
other libzstd (a system one loaded by a dependency) without either interposing the other.
EOF
echo "==> done: zstd $VERSION"
