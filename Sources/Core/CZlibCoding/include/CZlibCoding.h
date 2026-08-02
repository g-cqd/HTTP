//
//  CZlibCoding.h
//  CZlibCoding
//
//  Gzip (RFC 1952) compression — one-shot AND resumable — plus gzip/zlib/raw inflate over the system
//  zlib, for the Linux content-coding path where Apple's Compression framework is absent (G0). zlib is
//  already linked (CCRC32 / CWSDeflate); this keeps the `deflateInit2`/`inflateInit2` plumbing in
//  auditable C, like CZstd. The whole target is built only on the Linux graph (HTTPServer depends on it
//  `.when(platforms: [.linux])`), and the Swift side guards on `#if canImport(CZlibCoding)`.
//
//  The one-shot and resumable encoders share ONE `deflateInit2` call site (`czlib_deflate_begin` in
//  czlibcoding.c) rather than repeating its parameters. That is what makes their outputs byte-identical
//  a structural property instead of a coincidence two edits could break: zlib's DEFLATE output depends
//  on windowBits/memLevel/strategy/level and on the input, never on how the input was handed in, so long
//  as the resumable form only ever flushes with `Z_NO_FLUSH` until `Z_FINISH`.
//

#ifndef CZLIBCODING_H
#define CZLIBCODING_H

#include <stddef.h>
#include <stdint.h>

/// The worst-case gzip output size for `src_size` octets — `compressBound` plus slack for the gzip
/// header/trailer — so a single-pass ``czlib_gzip_compress`` always fits. Caller allocates this.
size_t czlib_compress_bound(size_t src_size);

/// One-shot gzip compress (RFC 1952; `deflateInit2` with windowBits 31) of `src[0..src_len)` into
/// `dst[0..dst_cap)` at `level`, returning the octets written, or 0 on any zlib error / `dst` too small
/// (fail-closed, so the Swift side reads it as "could not encode", mirroring Gzip/Brotli's nil). The
/// caller owns the buffers; no state is held across calls.
size_t czlib_gzip_compress(uint8_t *dst, size_t dst_cap, const uint8_t *src, size_t src_len, int level);

/// One-shot inflate of a gzip OR zlib stream (`inflateInit2` windowBits 47 = header auto-detect) of
/// `src[0..src_len)` into `dst[0..dst_cap)`, returning octets written or 0 on error / `dst` too small.
/// Backs the round-trip test and the inbound gzip/`deflate` (zlib-wrapped) request path. Caller owns buffers.
size_t czlib_inflate(uint8_t *dst, size_t dst_cap, const uint8_t *src, size_t src_len);

/// One-shot inflate of a raw DEFLATE stream (RFC 1951; `inflateInit2` windowBits -15) — the fallback for
/// a `deflate` sender that omits the zlib header. Returns octets written or 0 on error. Caller owns buffers.
size_t czlib_inflate_raw(uint8_t *dst, size_t dst_cap, const uint8_t *src, size_t src_len);

/// A resumable gzip encode — one `z_stream` plus the "has it ended" flag, opaque to the caller.
///
/// Incomplete by design: Swift imports a pointer to it as `OpaquePointer`, so the `z_stream` layout
/// never reaches the Swift side and the lifetime is exactly create/pump*/destroy.
typedef struct czlib_deflate_stream czlib_deflate_stream;

/// Starts a resumable gzip member (RFC 1952) at `level`, or NULL if zlib would not start one.
///
/// Initialized through the same ``czlib_deflate_begin`` as ``czlib_gzip_compress``, so a stream and a
/// one-shot at the same `level` are the same encoder — see the file header on byte-identity.
czlib_deflate_stream *czlib_deflate_stream_create(int level);

/// One `deflate()` call: takes from `src[0..src_len)`, writes into `dst[0..dst_cap)`.
///
/// Returns 1 on success and 0 on a zlib error, the "0 means could not encode" convention this header
/// uses throughout. `*consumed` and `*produced` report the octets actually moved (either may be 0 —
/// zlib legitimately absorbs input without emitting, and emits without absorbing). `*ended` is set to 1
/// once the member is complete, which only happens when `finish` is non-zero.
///
/// `finish` selects the flush mode, and the choice is load-bearing: 0 is `Z_NO_FLUSH`, which lets zlib
/// choose its own block boundaries exactly as the one-shot encoder does, and non-zero is `Z_FINISH`.
/// `Z_SYNC_FLUSH` is deliberately NOT offered — it would force a block boundary at every caller chunk
/// and make the output a function of the chunking (see the header note).
///
/// Call again whenever `*produced == dst_cap` (zlib had more to say than there was room for), and, when
/// finishing, until `*ended`. The caller owns both buffers; the stream owns nothing but its own state.
int czlib_deflate_stream_pump(
    czlib_deflate_stream *stream,
    const uint8_t *src, size_t src_len, size_t *consumed,
    uint8_t *dst, size_t dst_cap, size_t *produced,
    int finish, int *ended
);

/// Ends the stream and frees it (`deflateEnd` + `free`). NULL-tolerant; never call twice.
void czlib_deflate_stream_destroy(czlib_deflate_stream *stream);

#endif /* CZLIBCODING_H */
