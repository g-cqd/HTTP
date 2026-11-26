//
//  chttpzstd.c
//  CHTTPZstd
//
//  Compiles the vendored single-file libzstd (vendor/zstd.c, never edited — regenerate with scripts/vendor-zstd.sh)
//  with every one of its symbols hidden, then implements the `chttpzstd_` surface over its streaming API. Hiding the
//  library matters on Linux: a dependency may load a system libzstd (libcurl does), and a visible copy here would be
//  exported from the executable and interpose that library's own calls, or the reverse.
//

// Before any system header: glibc declares `qsort_r` (libzstd's dictionary builder) only under _GNU_SOURCE, and
// the vendored library's own definition comes too late once this file has included <stdlib.h>.
#if !defined(_GNU_SOURCE) && !defined(__ANDROID__)
#define _GNU_SOURCE
#endif

#include "CHTTPZstd.h"

// Every system header vendor/zstd.c includes, included first, so their include guards keep them out of the hidden
// region below: a C library declaration that picks up hidden visibility (`stderr`, `fprintf`, `memcmp`, ...) can
// only bind inside this binary, and the link against the shared libc fails (GNU ld reports them undefined).
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if defined(__unix__) || defined(__APPLE__)
#include <sys/times.h>
#include <unistd.h>
#endif
#if defined(__aarch64__) || defined(__ARM_NEON)
#include <arm_neon.h>
#endif
#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>
#endif

// vendor/zstd.c forward-declares ASan/MSan runtime hooks directly instead of including <sanitizer/*_interface.h>.
// Pre-declare them with default visibility before `#pragma GCC visibility push(hidden)` so GNU ld can bind them to
// libclang_rt.asan / libclang_rt.msan when building shared test bundles under `--sanitize=address` / `memory`.
__attribute__((visibility("default"))) void __asan_poison_memory_region(void const volatile *addr, size_t size);
__attribute__((visibility("default"))) void __asan_unpoison_memory_region(void const volatile *addr, size_t size);
__attribute__((visibility("default"))) void __msan_unpoison(const volatile void *a, size_t size);
__attribute__((visibility("default"))) void __msan_poison(const volatile void *a, size_t size);
__attribute__((visibility("default"))) intptr_t __msan_test_shadow(const volatile void *x, size_t size);
__attribute__((visibility("default"))) void __msan_print_shadow(const volatile void *x, size_t size);

// vendor/zstd.c is generated single-threaded (scripts/vendor-zstd.sh): no worker pool, no pthread dependency.
#define ZSTDLIB_VISIBLE __attribute__((visibility("hidden")))
#define ZSTDERRORLIB_VISIBLE __attribute__((visibility("hidden")))
#define ZDICTLIB_VISIBLE __attribute__((visibility("hidden")))
// Hidden: libzstd's API (through its visibility macros above) and its internal globals (through the pragma).
#pragma GCC visibility push(hidden)
#include "vendor/zstd.c"
#pragma GCC visibility pop

struct chttpzstd_cctx {
    ZSTD_CCtx *stream;
};

struct chttpzstd_dctx {
    ZSTD_DCtx *stream;
};

static long failure(size_t code) {
    switch (ZSTD_getErrorCode(code)) {
        case ZSTD_error_frameParameter_windowTooLarge:
            return CHTTPZSTD_ERROR_WINDOW_TOO_LARGE;
        case ZSTD_error_memory_allocation:
            return CHTTPZSTD_ERROR_MEMORY;
        case ZSTD_error_parameter_unsupported:
        case ZSTD_error_parameter_outOfBound:
            return CHTTPZSTD_ERROR_PARAMETER;
        case ZSTD_error_prefix_unknown:
        case ZSTD_error_frameParameter_unsupported:
        case ZSTD_error_corruption_detected:
        case ZSTD_error_checksum_wrong:
        case ZSTD_error_literals_headerWrong:
        case ZSTD_error_dictionary_corrupted:
        case ZSTD_error_dictionary_wrong:
        case ZSTD_error_srcSize_wrong:
            return CHTTPZSTD_ERROR_CORRUPT;
        default:
            return CHTTPZSTD_ERROR_OTHER;
    }
}

int chttpzstd_min_level(void) { return ZSTD_minCLevel(); }

size_t chttpzstd_compress_bound(size_t size) {
    const size_t bound = ZSTD_compressBound(size);
    return ZSTD_isError(bound) ? 0 : bound;
}

int chttpzstd_max_level(void) { return ZSTD_maxCLevel(); }

uint64_t chttpzstd_frame_content_size(const uint8_t *src, size_t size) {
    const unsigned long long declared = ZSTD_getFrameContentSize(src, size);
    if (declared == ZSTD_CONTENTSIZE_UNKNOWN) return CHTTPZSTD_CONTENT_SIZE_UNKNOWN;
    if (declared == ZSTD_CONTENTSIZE_ERROR) return CHTTPZSTD_CONTENT_SIZE_ERROR;
    return (uint64_t)declared;
}

chttpzstd_cctx *chttpzstd_cctx_create(int level) {
    if (level < ZSTD_minCLevel() || level > ZSTD_maxCLevel()) return NULL;
    chttpzstd_cctx *ctx = malloc(sizeof *ctx);
    if (!ctx) return NULL;
    ctx->stream = ZSTD_createCCtx();
    if (!ctx->stream || ZSTD_isError(ZSTD_CCtx_setParameter(ctx->stream, ZSTD_c_compressionLevel, level)) ||
        ZSTD_isError(ZSTD_CCtx_setParameter(ctx->stream, ZSTD_c_contentSizeFlag, 0))) {
        chttpzstd_cctx_free(ctx);
        return NULL;
    }
    return ctx;
}

void chttpzstd_cctx_free(chttpzstd_cctx *ctx) {
    if (!ctx) return;
    ZSTD_freeCCtx(ctx->stream);
    free(ctx);
}

int chttpzstd_cctx_reset(chttpzstd_cctx *ctx) {
    const size_t result = ZSTD_CCtx_reset(ctx->stream, ZSTD_reset_session_only);
    return ZSTD_isError(result) ? (int)failure(result) : 0;
}

long chttpzstd_compress_stream(chttpzstd_cctx *ctx, const uint8_t *src, size_t size, size_t *consumed, uint8_t *dst,
                               size_t capacity, size_t *produced, int end) {
    ZSTD_inBuffer in = {src, size, *consumed};
    ZSTD_outBuffer out = {dst, capacity, *produced};
    long status;
    // `continue` until the input is consumed, then `end`: the frame is the same however the input was chunked.
    for (;;) {
        if (in.pos < in.size || !end) {
            const size_t result = ZSTD_compressStream2(ctx->stream, &out, &in, ZSTD_e_continue);
            if (ZSTD_isError(result)) {
                status = failure(result);
                break;
            }
            if (in.pos < in.size) {
                if (out.pos == out.size) {
                    status = 1;  // the output is full with input left
                    break;
                }
                continue;
            }
            if (!end) {
                status = 0;  // all input taken; the rest waits in the context for more input or the end
                break;
            }
        }
        const size_t remaining = ZSTD_compressStream2(ctx->stream, &out, &in, ZSTD_e_end);
        if (ZSTD_isError(remaining)) {
            status = failure(remaining);
            break;
        }
        if (remaining == 0) {
            status = 0;  // the frame is complete
            break;
        }
        if (out.pos == out.size) {
            status = 1;  // more of the frame to write once there is room
            break;
        }
    }
    *consumed = in.pos;
    *produced = out.pos;
    return status;
}

chttpzstd_dctx *chttpzstd_dctx_create(unsigned window_log_max) {
    if (window_log_max < 10 || window_log_max > 31) return NULL;
    chttpzstd_dctx *ctx = malloc(sizeof *ctx);
    if (!ctx) return NULL;
    ctx->stream = ZSTD_createDCtx();
    if (!ctx->stream || ZSTD_isError(ZSTD_DCtx_setParameter(ctx->stream, ZSTD_d_windowLogMax, (int)window_log_max))) {
        chttpzstd_dctx_free(ctx);
        return NULL;
    }
    return ctx;
}

void chttpzstd_dctx_free(chttpzstd_dctx *ctx) {
    if (!ctx) return;
    ZSTD_freeDCtx(ctx->stream);
    free(ctx);
}

int chttpzstd_dctx_reset(chttpzstd_dctx *ctx) {
    const size_t result = ZSTD_DCtx_reset(ctx->stream, ZSTD_reset_session_only);
    return ZSTD_isError(result) ? (int)failure(result) : 0;
}

long chttpzstd_decompress_stream(chttpzstd_dctx *ctx, const uint8_t *src, size_t size, size_t *consumed, uint8_t *dst,
                                 size_t capacity, size_t *produced) {
    ZSTD_inBuffer in = {src, size, *consumed};
    ZSTD_outBuffer out = {dst, capacity, *produced};
    const size_t result = ZSTD_decompressStream(ctx->stream, &out, &in);
    *consumed = in.pos;
    *produced = out.pos;
    if (ZSTD_isError(result)) return failure(result);
    return result == 0 ? 0 : (long)(result > LONG_MAX ? LONG_MAX : result);
}
