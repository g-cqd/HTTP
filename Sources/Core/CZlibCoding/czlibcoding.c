//
//  czlibcoding.c
//  CZlibCoding
//
//  RFC 1952 gzip content coding (and gzip/zlib/raw inflate) over the system zlib, one-shot. Every entry
//  point is a thin wrapper that funnels zlib's return codes to "octets written, or 0 on failure" so the
//  Swift side reads 0 as "could not encode/decode" (mirroring CZstd / the nil of Gzip/Brotli). No state
//  is held across calls; the caller owns the buffers. `avail_in`/`avail_out` are `uInt` (32-bit), which
//  bounds a single call to 4 GiB — far above any `maxBodySize`-capped HTTP body, the only caller.
//

#include "CZlibCoding.h"

#include <string.h>
#include <zlib.h>

size_t czlib_compress_bound(size_t src_size) {
    // compressBound is the zlib-wrapper bound; gzip's header(10)+trailer(8) exceed zlib's 6, so add slack.
    return compressBound((uLong)src_size) + 32;
}

size_t czlib_gzip_compress(
    uint8_t *dst, size_t dst_cap, const uint8_t *src, size_t src_len, int level
) {
    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    // windowBits 15 + 16 selects the gzip wrapper (RFC 1952); memLevel 8 is zlib's default.
    if (deflateInit2(&stream, level, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        return 0;
    }
    stream.next_in = (Bytef *)src;
    stream.avail_in = (uInt)src_len;
    stream.next_out = dst;
    stream.avail_out = (uInt)dst_cap;
    int rc = deflate(&stream, Z_FINISH);
    size_t written = dst_cap - stream.avail_out;
    deflateEnd(&stream);
    return rc == Z_STREAM_END ? written : 0;  // not Z_STREAM_END ⇒ dst too small / error: fail closed
}

static size_t czlib_inflate_window(
    uint8_t *dst, size_t dst_cap, const uint8_t *src, size_t src_len, int window_bits
) {
    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    if (inflateInit2(&stream, window_bits) != Z_OK) {
        return 0;
    }
    stream.next_in = (Bytef *)src;
    stream.avail_in = (uInt)src_len;
    stream.next_out = dst;
    stream.avail_out = (uInt)dst_cap;
    int rc = inflate(&stream, Z_FINISH);
    size_t written = dst_cap - stream.avail_out;
    inflateEnd(&stream);
    return rc == Z_STREAM_END ? written : 0;  // truncated / bad stream / dst too small: fail closed
}

size_t czlib_inflate(uint8_t *dst, size_t dst_cap, const uint8_t *src, size_t src_len) {
    return czlib_inflate_window(dst, dst_cap, src, src_len, 15 + 32);  // 32 ⇒ auto-detect gzip/zlib
}

size_t czlib_inflate_raw(uint8_t *dst, size_t dst_cap, const uint8_t *src, size_t src_len) {
    return czlib_inflate_window(dst, dst_cap, src, src_len, -15);  // negative ⇒ raw DEFLATE, no header
}
