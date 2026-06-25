//
//  CWSDeflate.c
//  CWSDeflate
//
//  RFC 7692 raw-DEFLATE over zlib. `deflateInit2`/`inflateInit2` with a negative windowBits select the
//  raw RFC 1951 stream (no zlib header/trailer). Compression uses `Z_SYNC_FLUSH` so each message ends on
//  a byte boundary with the `00 00 ff ff` empty-block tail RFC 7692 §7.2.1 strips; decompression uses
//  `Z_NO_FLUSH` after the caller re-appends that tail (§7.2.2). The stream is kept alive across messages
//  for context-takeover; `*_reset` clears the history for `no_context_takeover`.
//

#include "CWSDeflate.h"

#include <stdlib.h>
#include <zlib.h>

struct cws_deflate {
    z_stream strm;
};

struct cws_inflate {
    z_stream strm;
};

cws_deflate *cws_deflate_new(int window_bits) {
    cws_deflate *z = calloc(1, sizeof(cws_deflate));
    if (z == NULL) {
        return NULL;
    }
    // Negative windowBits → raw DEFLATE (RFC 1951), no zlib header/trailer (RFC 7692 §7).
    if (deflateInit2(&z->strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -window_bits, 8,
                     Z_DEFAULT_STRATEGY) != Z_OK) {
        free(z);
        return NULL;
    }
    return z;
}

cws_inflate *cws_inflate_new(int window_bits) {
    cws_inflate *z = calloc(1, sizeof(cws_inflate));
    if (z == NULL) {
        return NULL;
    }
    if (inflateInit2(&z->strm, -window_bits) != Z_OK) {
        free(z);
        return NULL;
    }
    return z;
}

void cws_deflate_free(cws_deflate *z) {
    if (z != NULL) {
        deflateEnd(&z->strm);
        free(z);
    }
}

void cws_inflate_free(cws_inflate *z) {
    if (z != NULL) {
        inflateEnd(&z->strm);
        free(z);
    }
}

int cws_deflate_reset(cws_deflate *z) {
    return deflateReset(&z->strm);
}

int cws_inflate_reset(cws_inflate *z) {
    return inflateReset(&z->strm);
}

void cws_deflate_input(cws_deflate *z, const uint8_t *src, size_t len) {
    z->strm.next_in = (Bytef *)src;  // deflate never writes through next_in
    z->strm.avail_in = (uInt)len;
}

void cws_inflate_input(cws_inflate *z, const uint8_t *src, size_t len) {
    z->strm.next_in = (Bytef *)src;
    z->strm.avail_in = (uInt)len;
}

ptrdiff_t cws_deflate_run(cws_deflate *z, uint8_t *dst, size_t cap, int *done) {
    z->strm.next_out = dst;
    z->strm.avail_out = (uInt)cap;
    int rc = deflate(&z->strm, Z_SYNC_FLUSH);
    if (rc != Z_OK && rc != Z_BUF_ERROR) {
        *done = 1;
        return -1;
    }
    // Done when all input is consumed and the flush produced no more output (avail_out left).
    *done = (z->strm.avail_in == 0 && z->strm.avail_out != 0) ? 1 : 0;
    return (ptrdiff_t)(cap - z->strm.avail_out);
}

ptrdiff_t cws_inflate_run(cws_inflate *z, uint8_t *dst, size_t cap, int *done) {
    z->strm.next_out = dst;
    z->strm.avail_out = (uInt)cap;
    int rc = inflate(&z->strm, Z_NO_FLUSH);
    if (rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR) {
        *done = 1;
        return -1;  // Z_DATA_ERROR / Z_MEM_ERROR / Z_NEED_DICT — a malformed stream
    }
    *done = ((z->strm.avail_in == 0 && z->strm.avail_out != 0) || rc == Z_STREAM_END) ? 1 : 0;
    return (ptrdiff_t)(cap - z->strm.avail_out);
}
