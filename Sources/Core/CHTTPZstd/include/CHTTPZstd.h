//
//  CHTTPZstd.h
//  CHTTPZstd
//
//  The C surface of the vendored Zstandard library (RFC 8878, upstream libzstd — see vendor/VENDORED.md), reduced
//  to what HTTPZstd needs: a compression context driven as a stream (one-shot encodes go through it too, so a body
//  coded whole and coded in chunks is byte-identical), a bounded decompression context, and the frame header's
//  declared size. Every libzstd symbol is hidden; only these `chttpzstd_` functions are visible.
//

#ifndef CHTTPZSTD_H
#define CHTTPZSTD_H

#include <stddef.h>
#include <stdint.h>

/// Failure codes, as negative returns.
#define CHTTPZSTD_ERROR_CORRUPT (-1)         ///< malformed, truncated where it cannot be, or checksum mismatch
#define CHTTPZSTD_ERROR_WINDOW_TOO_LARGE (-2) ///< the frame's window exceeds the context's limit
#define CHTTPZSTD_ERROR_MEMORY (-3)           ///< an allocation failed
#define CHTTPZSTD_ERROR_PARAMETER (-4)        ///< an invalid level or parameter
#define CHTTPZSTD_ERROR_OTHER (-5)            ///< any other libzstd error

/// `chttpzstd_frame_content_size` results that are not sizes.
#define CHTTPZSTD_CONTENT_SIZE_UNKNOWN UINT64_MAX
#define CHTTPZSTD_CONTENT_SIZE_ERROR (UINT64_MAX - 1)

/// The smallest and largest compression levels the library accepts.
int chttpzstd_min_level(void);
int chttpzstd_max_level(void);

/// The largest frame `size` input bytes can compress to (any level), or 0 when `size` exceeds what a frame can hold.
size_t chttpzstd_compress_bound(size_t size);

/// The size the first frame of `src[0 ..< size]` declares, `CHTTPZSTD_CONTENT_SIZE_UNKNOWN` when it declares none,
/// or `CHTTPZSTD_CONTENT_SIZE_ERROR` when `src` does not start with a valid frame header.
uint64_t chttpzstd_frame_content_size(const uint8_t *src, size_t size);

typedef struct chttpzstd_cctx chttpzstd_cctx;

/// A compression context at `level` that writes no content size into its frames (a stream's size is not known up
/// front, and a one-shot encode must match it); NULL when the level is invalid or memory is short.
chttpzstd_cctx *chttpzstd_cctx_create(int level);
void chttpzstd_cctx_free(chttpzstd_cctx *ctx);
/// Abandons any frame in progress; the next call starts a new frame with the same parameters (tables are kept, so a
/// reused context does not clear them again).
int chttpzstd_cctx_reset(chttpzstd_cctx *ctx);

/// Compresses `src[0 ..< size]` into `dst[*produced ..< capacity]`, advancing `*consumed` (from 0) and `*produced`.
/// With `end` nonzero the frame is finished once the input is consumed. Returns 0 when the input is consumed and,
/// with `end`, the frame is complete; a positive value when more output room is needed (call again); a negative
/// `CHTTPZSTD_ERROR_*` on failure.
long chttpzstd_compress_stream(chttpzstd_cctx *ctx, const uint8_t *src, size_t size, size_t *consumed, uint8_t *dst,
                               size_t capacity, size_t *produced, int end);

typedef struct chttpzstd_dctx chttpzstd_dctx;

/// A decompression context that rejects frames whose window exceeds `1 << window_log_max` (10 ... 31), so a
/// hostile header cannot make it allocate more; NULL when memory is short.
chttpzstd_dctx *chttpzstd_dctx_create(unsigned window_log_max);
void chttpzstd_dctx_free(chttpzstd_dctx *ctx);
/// Abandons any frame in progress (and forgets the frames before it).
int chttpzstd_dctx_reset(chttpzstd_dctx *ctx);

/// Decompresses from `src[*consumed ..< size]` into `dst[*produced ..< capacity]`, advancing both. Returns 0 when a
/// frame has been completely decoded and flushed, a positive value while it is not (more input, or more output room),
/// or a negative `CHTTPZSTD_ERROR_*`.
long chttpzstd_decompress_stream(chttpzstd_dctx *ctx, const uint8_t *src, size_t size, size_t *consumed, uint8_t *dst,
                                 size_t capacity, size_t *produced);

#endif /* CHTTPZSTD_H */
