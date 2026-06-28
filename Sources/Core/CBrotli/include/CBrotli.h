//
//  CBrotli.h
//  CBrotli
//
//  A thin C shim over libbrotli (encoder + decoder) for the RFC 7932 `br` content coding on the non-Apple
//  (Linux) path, where Apple's Compression framework — which provides Brotli on Darwin — is absent. One-
//  shot, like CZstd: each entry point funnels libbrotli's boolean/enum results to "octets written, or 0
//  on failure" so the Swift side reads 0 as "could not encode/decode". The whole target is opt-in via the
//  `HTTP_BROTLI` build flag, so the default build graph never links libbrotli; the Swift integration
//  guards on `#if canImport(CBrotli)`. The caller owns the buffers; no state is held across calls.
//

#ifndef CBROTLI_H
#define CBROTLI_H

#include <stddef.h>
#include <stdint.h>

/// The worst-case compressed size for `src_size` octets (`BrotliEncoderMaxCompressedSize`), so a single-
/// pass ``cbrotli_compress`` always fits, or 0 when no bound exists (input too large). Caller allocates it.
size_t cbrotli_compress_bound(size_t src_size);

/// One-shot Brotli compress (RFC 7932) of `src[0..src_len)` into `dst[0..dst_cap)` at `quality` (0–11),
/// returning octets written, or 0 on any libbrotli failure / `dst` too small (fail-closed). `dst_cap`
/// should be at least ``cbrotli_compress_bound(src_len)``.
size_t cbrotli_compress(uint8_t *dst, size_t dst_cap, const uint8_t *src, size_t src_len, int quality);

/// One-shot Brotli decompress of `src[0..src_len)` into `dst[0..dst_cap)`, returning octets written, or 0
/// on any libbrotli failure / `dst` too small (the latter is the decompression-bomb signal: a buffer sized
/// to the cap rejects an over-cap expansion). The inverse of ``cbrotli_compress``.
size_t cbrotli_decompress(uint8_t *dst, size_t dst_cap, const uint8_t *src, size_t src_len);

#endif /* CBROTLI_H */
