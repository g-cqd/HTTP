//
//  CZstd.h
//  CZstd
//
//  A thin C shim over the system libzstd for the RFC 8878 `zstd` content coding. Apple's
//  Compression framework has no Zstandard codec, so — like CCRC32 / CWSDeflate over the system
//  zlib — the unsafe one-shot `ZSTD_compress` plumbing is kept in auditable C, linking `-lzstd`.
//  The middleware uses only the compressor (the server emits `zstd`, never inflates it here); the
//  matching single-frame decompressor is provided so a round-trip test can verify a produced frame
//  against the real library (the inbound `zstd` request path is a separate, future concern). The
//  whole `CZstd` target is opt-in via the `HTTP_ZSTD` build flag, so the default build graph never
//  sees libzstd; the Swift integration guards on `#if canImport(CZstd)`.
//

#ifndef CZSTD_H
#define CZSTD_H

#include <stddef.h>
#include <stdint.h>

/// The worst-case compressed size for `src_size` octets — the destination capacity a single-pass
/// ``czstd_compress`` needs so the frame always fits (wraps `ZSTD_compressBound`). Returns 0 when
/// the bound itself fails (`ZSTD_isError`), e.g. an input above zstd's maximum.
size_t czstd_compress_bound(size_t src_size);

/// Compresses `src[0..src_len)` into a single zstd frame (RFC 8878 §3) in `dst[0..dst_cap)` at
/// compression `level`, returning the octets written, or 0 on any libzstd error (`ZSTD_isError`,
/// reported when the frame does not fit `dst_cap` or `level` is invalid). `dst_cap` should be at
/// least ``czstd_compress_bound(src_len)``. A pure wrapper over `ZSTD_compress`; the caller owns
/// the buffers.
size_t czstd_compress(uint8_t *dst, size_t dst_cap, const uint8_t *src, size_t src_len, int level);

/// The library's maximum compression level (`ZSTD_maxCLevel`) — for clamping a requested level.
int czstd_max_level(void);

/// Decompresses a single zstd frame `src[0..src_len)` (RFC 8878 §3) into `dst[0..dst_cap)`,
/// returning the octets written, or 0 on any libzstd error (`ZSTD_isError`, e.g. `dst_cap` smaller
/// than the frame's content size). The inverse of ``czstd_compress``, used to verify a round-trip
/// against the real library. The middleware does not call this (it only encodes); the caller owns
/// the buffers.
size_t czstd_decompress(uint8_t *dst, size_t dst_cap, const uint8_t *src, size_t src_len);

/// The declared decompressed size of the frame `src[0..src_len)` (`ZSTD_getFrameContentSize`), or 0
/// when it is unknown or `src` is not a valid frame — a safe destination size for
/// ``czstd_decompress`` when the producer wrote the size (zstd's one-shot `ZSTD_compress` always
/// does).
size_t czstd_frame_content_size(const uint8_t *src, size_t src_len);

#endif /* CZSTD_H */
