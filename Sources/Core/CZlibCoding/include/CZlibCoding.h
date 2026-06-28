//
//  CZlibCoding.h
//  CZlibCoding
//
//  One-shot gzip (RFC 1952) compression + gzip/zlib/raw inflate over the system zlib, for the Linux
//  content-coding path where Apple's Compression framework is absent (G0). zlib is already linked
//  (CCRC32 / CWSDeflate); this keeps the one-shot `deflateInit2`/`inflateInit2` plumbing in auditable C,
//  like CZstd. The whole target is built only on the Linux graph (HTTPServer depends on it
//  `.when(platforms: [.linux])`), and the Swift side guards on `#if canImport(CZlibCoding)`.
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

#endif /* CZLIBCODING_H */
