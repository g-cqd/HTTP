# Vendored Zstandard

- Upstream: https://github.com/facebook/zstd, release `v1.5.7`
- Tarball: `zstd-1.5.7.tar.gz`, SHA-256 `eb33e51f49a15e023950cd7825ca74a4a2b43db8354825ac24fc1b7ee09e6fa3` (verified against the pinned value)
- `zstd.c`: generated with `build/single_file_libs/combine.py -r ../../lib -x legacy/zstd_legacy.h` from upstream's
  `zstd-in.c` template with its `#define ZSTD_MULTITHREAD` line commented out (single-threaded: no worker pool, no
  pthread dependency) — compressor, decompressor and dictionary builder; no legacy formats; no assembly
  (`ZSTD_DISABLE_ASM`)
- `zstd.h`, `zstd_errors.h`: copied verbatim from `lib/`
- License: BSD (`LICENSE`), selected from upstream's BSD-or-GPLv2 dual license

Regenerate with `scripts/vendor-zstd.sh <version> <sha256>`; never edit these files by hand. The shim
(`../chttpzstd.c`) compiles `zstd.c` with every libzstd symbol hidden, so this copy can share a process with any
other libzstd (a system one loaded by a dependency) without either interposing the other.
