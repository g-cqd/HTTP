//
//  CWSDeflate.h
//  CWSDeflate
//
//  A thin C shim over the system zlib (already linked by CCRC32) for RFC 7692 permessage-deflate. zlib
//  is the only DEFLATE backend that exposes `Z_SYNC_FLUSH` — the flush mode RFC 7692 §7.2.1 frames a
//  message with (Apple's Compression framework cannot, proven by probe) — so the WebSocket layer drives
//  raw DEFLATE (negative windowBits, RFC 1951, no zlib header) through here. A stream persists its LZ77
//  history across messages (context-takeover); the WebSocket layer calls the reset functions per message
//  for `no_context_takeover`. The unsafe `z_stream` plumbing stays in C, auditable like CCRC32.
//

#ifndef CWSDEFLATE_H
#define CWSDEFLATE_H

#include <stddef.h>
#include <stdint.h>

/// An opaque streaming raw-DEFLATE compressor (RFC 1951 / RFC 7692 §7.2.1).
typedef struct cws_deflate cws_deflate;

/// An opaque streaming raw-DEFLATE decompressor (RFC 1951 / RFC 7692 §7.2.2).
typedef struct cws_inflate cws_inflate;

/// Creates a compressor with the given window (8…15; applied as a negative raw-DEFLATE window).
/// Returns NULL on allocation/zlib failure.
cws_deflate *cws_deflate_new(int window_bits);

/// Creates a decompressor with the given window (8…15). Returns NULL on failure.
cws_inflate *cws_inflate_new(int window_bits);

/// Frees a compressor/decompressor (NULL-safe).
void cws_deflate_free(cws_deflate *z);
void cws_inflate_free(cws_inflate *z);

/// Resets the LZ77 history for `no_context_takeover` (RFC 7692 §7.1.1). Returns 0 on success.
int cws_deflate_reset(cws_deflate *z);
int cws_inflate_reset(cws_inflate *z);

/// Points the stream at `src[0..len)`, held by reference until consumed across `run` calls.
void cws_deflate_input(cws_deflate *z, const uint8_t *src, size_t len);
void cws_inflate_input(cws_inflate *z, const uint8_t *src, size_t len);

/// Compresses pending input into `dst[0..cap)` with `Z_SYNC_FLUSH`; returns the octets written, or -1
/// on a stream error. Sets `*done` to 1 once the flush has fully drained (all input consumed, output
/// stalled) — the caller then strips the trailing `00 00 ff ff` per RFC 7692 §7.2.1.
ptrdiff_t cws_deflate_run(cws_deflate *z, uint8_t *dst, size_t cap, int *done);

/// Inflates pending input into `dst[0..cap)`; returns the octets written, or -1 on a stream error. Sets
/// `*done` to 1 once input is consumed and output stalls (RFC 7692 §7.2.2). The caller appends the
/// `00 00 ff ff` boundary before the message and bounds the accumulated output (CWE-409).
ptrdiff_t cws_inflate_run(cws_inflate *z, uint8_t *dst, size_t cap, int *done);

#endif /* CWSDEFLATE_H */
