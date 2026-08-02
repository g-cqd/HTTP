//
//  czlibcoding.c
//  CZlibCoding
//
//  RFC 1952 gzip content coding (and gzip/zlib/raw inflate) over the system zlib. The inflate side and
//  the buffered encode are one-shot; the encode side ALSO has a resumable form for streamed response
//  bodies. Every entry point funnels zlib's return codes to "octets written / 1, or 0 on failure" so the
//  Swift side reads 0 as "could not encode/decode" (mirroring CZstd / the nil of Gzip/Brotli). The caller
//  owns the buffers. `avail_in`/`avail_out` are `uInt` (32-bit), so each call is clamped to 4 GiB — far
//  above any `maxBodySize`-capped HTTP body, the only caller — and the resumable form simply loops.
//
//  BYTE-IDENTITY, and why it is structural. `czlib_gzip_compress` and `czlib_deflate_stream_create`
//  share ONE `deflateInit2` call site, `czlib_deflate_begin`, so neither can drift from the other by an
//  edit to one of them. Given identical init parameters, zlib's DEFLATE output is a function of the
//  input octets alone as long as the resumable form flushes only with `Z_NO_FLUSH` until `Z_FINISH`:
//  `deflate_slow` refuses to emit while `lookahead < MIN_LOOKAHEAD` under `Z_NO_FLUSH` (deflate.c), so a
//  chunk boundary can never truncate a match, and block boundaries are taken when the symbol buffer
//  fills — a property of the input, not of how it arrived. `Z_SYNC_FLUSH` would break exactly this by
//  forcing a stored-block boundary per chunk, which is why no entry point here offers it.
//

#include "CZlibCoding.h"

#include <stdlib.h>
#include <string.h>
#include <zlib.h>

/// Initializes `stream` as a gzip (RFC 1952) deflate encoder at `level` — the ONE place the encoder's
/// parameters are written, so the one-shot and resumable forms cannot disagree about them.
///
/// windowBits 15 + 16 selects the gzip wrapper (zlib emits the 10-octet header and the CRC-32 + ISIZE
/// trailer itself); memLevel 8 and `Z_DEFAULT_STRATEGY` are zlib's defaults.
static int czlib_deflate_begin(z_stream *stream, int level) {
    memset(stream, 0, sizeof(*stream));
    return deflateInit2(stream, level, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY);
}

/// The largest octet count one `deflate()` call can be handed, `uInt` being 32-bit.
static uInt czlib_clamp(size_t count) {
    return count > (size_t)0xFFFFFFFFu ? (uInt)0xFFFFFFFFu : (uInt)count;
}

size_t czlib_compress_bound(size_t src_size) {
    // compressBound is the zlib-wrapper bound; gzip's header(10)+trailer(8) exceed zlib's 6, so add slack.
    return compressBound((uLong)src_size) + 32;
}

size_t czlib_gzip_compress(
    uint8_t *dst, size_t dst_cap, const uint8_t *src, size_t src_len, int level
) {
    z_stream stream;
    if (czlib_deflate_begin(&stream, level) != Z_OK) {
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

// MARK: - The resumable encoder

struct czlib_deflate_stream {
    z_stream zs;
    int ended;  // 1 once `deflate` has returned Z_STREAM_END; the member is complete and spent
};

czlib_deflate_stream *czlib_deflate_stream_create(int level) {
    czlib_deflate_stream *stream = calloc(1, sizeof(*stream));
    if (stream == NULL) {
        return NULL;
    }
    if (czlib_deflate_begin(&stream->zs, level) != Z_OK) {
        free(stream);  // deflateInit2 failing means there is nothing for deflateEnd to release
        return NULL;
    }
    return stream;
}

int czlib_deflate_stream_pump(
    czlib_deflate_stream *stream,
    const uint8_t *src, size_t src_len, size_t *consumed,
    uint8_t *dst, size_t dst_cap, size_t *produced,
    int finish, int *ended
) {
    *consumed = 0;
    *produced = 0;
    *ended = 0;
    if (stream == NULL || stream->ended) {
        return 0;  // a spent stream is a caller defect, reported the same way as a zlib error
    }
    uInt taking = czlib_clamp(src_len);
    uInt room = czlib_clamp(dst_cap);
    stream->zs.next_in = (Bytef *)src;
    stream->zs.avail_in = taking;
    stream->zs.next_out = dst;
    stream->zs.avail_out = room;
    // Z_NO_FLUSH, never Z_SYNC_FLUSH — see the byte-identity note in this file's header.
    int rc = deflate(&stream->zs, finish ? Z_FINISH : Z_NO_FLUSH);
    *consumed = (size_t)(taking - stream->zs.avail_in);
    *produced = (size_t)(room - stream->zs.avail_out);
    if (rc == Z_STREAM_END) {
        stream->ended = 1;
        *ended = 1;
        return 1;
    }
    // Z_BUF_ERROR is "no progress was possible", which for a Z_NO_FLUSH pump with nothing left to give
    // is the normal way to say "done for now" rather than a failure.
    return (rc == Z_OK || rc == Z_BUF_ERROR) ? 1 : 0;
}

void czlib_deflate_stream_destroy(czlib_deflate_stream *stream) {
    if (stream == NULL) {
        return;
    }
    deflateEnd(&stream->zs);
    free(stream);
}
