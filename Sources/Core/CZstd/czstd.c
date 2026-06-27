//
//  czstd.c
//  CZstd
//
//  RFC 8878 `zstd` content coding over the system libzstd (one-shot, single frame). Every entry
//  point is a thin wrapper that funnels libzstd's `size_t` error codes through `ZSTD_isError`,
//  returning 0 on failure so the Swift side reads it as "could not encode" (mirroring the nil of
//  Gzip/Brotli). No state is held across calls; the caller owns the buffers. The middleware uses
//  only the compressor; the decompressor backs the round-trip verification test (the inbound `zstd`
//  request path is a future concern).
//

#include "CZstd.h"

#include <zstd.h>

size_t czstd_compress_bound(size_t src_size) {
    size_t bound = ZSTD_compressBound(src_size);
    if (ZSTD_isError(bound)) {
        return 0;  // src_size above ZSTD_MAX_INPUT_SIZE — signal "no bound" to the caller
    }
    return bound;
}

size_t czstd_compress(uint8_t *dst, size_t dst_cap, const uint8_t *src, size_t src_len, int level) {
    size_t written = ZSTD_compress(dst, dst_cap, src, src_len, level);
    if (ZSTD_isError(written)) {
        return 0;  // dst too small, bad level, or an internal error — fail closed
    }
    return written;
}

int czstd_max_level(void) {
    return ZSTD_maxCLevel();
}

size_t czstd_decompress(uint8_t *dst, size_t dst_cap, const uint8_t *src, size_t src_len) {
    size_t written = ZSTD_decompress(dst, dst_cap, src, src_len);
    if (ZSTD_isError(written)) {
        return 0;  // not a valid frame, or dst smaller than the content size — fail closed
    }
    return written;
}

size_t czstd_frame_content_size(const uint8_t *src, size_t src_len) {
    unsigned long long size = ZSTD_getFrameContentSize(src, src_len);
    // ZSTD_CONTENTSIZE_UNKNOWN (0ULL - 1) / ZSTD_CONTENTSIZE_ERROR (0ULL - 2) — collapse both to 0.
    if (size == ZSTD_CONTENTSIZE_UNKNOWN || size == ZSTD_CONTENTSIZE_ERROR) {
        return 0;
    }
    return (size_t)size;
}
