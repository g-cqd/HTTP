//
//  crc32.c
//  CCRC32
//
//  gzip CRC-32 (RFC 1952 §8; reflected polynomial 0xEDB88320). One portable reference (slicing-by-8)
//  plus hardware backends (ARMv8 CRC32 instructions; zlib's PCLMULQDQ on x86). All one-shot, all
//  returning the final conditioned checksum, all agreeing bit-for-bit.
//

#include "CCRC32.h"

#include <pthread.h>
#include <zlib.h>

// MARK: - Portable slicing-by-8 table (the reference; always correct)

static uint32_t kTable[8][256];
static pthread_once_t kOnce = PTHREAD_ONCE_INIT;

static void build_tables(void) {
    for (int n = 0; n < 256; ++n) {
        uint32_t c = (uint32_t)n;
        for (int k = 0; k < 8; ++k) {
            c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        }
        kTable[0][n] = c;
    }
    for (int n = 0; n < 256; ++n) {
        uint32_t c = kTable[0][n];
        for (int k = 1; k < 8; ++k) {
            c = kTable[0][c & 0xFFu] ^ (c >> 8);
            kTable[k][n] = c;
        }
    }
}

static inline uint32_t load_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

uint32_t ccrc32_slice8(const uint8_t *buf, size_t len) {
    pthread_once(&kOnce, build_tables);
    uint32_t crc = 0xFFFFFFFFu;
    while (len >= 8) {
        crc ^= load_le32(buf);
        uint32_t hi = load_le32(buf + 4);
        crc = kTable[7][crc & 0xFFu] ^ kTable[6][(crc >> 8) & 0xFFu]
            ^ kTable[5][(crc >> 16) & 0xFFu] ^ kTable[4][(crc >> 24) & 0xFFu]
            ^ kTable[3][hi & 0xFFu] ^ kTable[2][(hi >> 8) & 0xFFu]
            ^ kTable[1][(hi >> 16) & 0xFFu] ^ kTable[0][(hi >> 24) & 0xFFu];
        buf += 8;
        len -= 8;
    }
    while (len--) {
        crc = kTable[0][(crc ^ *buf++) & 0xFFu] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFu;
}

// The naive one-octet-at-a-time table (the original algorithm) — the comparison baseline.
uint32_t ccrc32_slice1(const uint8_t *buf, size_t len) {
    pthread_once(&kOnce, build_tables);
    uint32_t crc = 0xFFFFFFFFu;
    while (len--) {
        crc = kTable[0][(crc ^ *buf++) & 0xFFu] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFu;
}

// MARK: - zlib (correct polynomial; internally hardware-accelerated)

uint32_t ccrc32_zlib(const uint8_t *buf, size_t len) {
    uLong crc = crc32(0L, Z_NULL, 0);
    while (len > 0) {  // zlib's length arg is 32-bit; chunk so huge buffers stay correct
        uInt chunk = (len > 0x7FFFFFFFu) ? 0x7FFFFFFFu : (uInt)len;
        crc = crc32(crc, buf, chunk);
        buf += chunk;
        len -= chunk;
    }
    return (uint32_t)crc;
}

// MARK: - ARMv8 CRC32 instructions

#if defined(__aarch64__)
#include <arm_acle.h>
__attribute__((target("crc")))
static uint32_t crc32_arm_hw(const uint8_t *buf, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    while (len >= 8) {
        uint64_t v;
        __builtin_memcpy(&v, buf, 8);  // little-endian; __crc32d consumes bytes low-to-high
        crc = __crc32d(crc, v);
        buf += 8;
        len -= 8;
    }
    if (len >= 4) {
        uint32_t v;
        __builtin_memcpy(&v, buf, 4);
        crc = __crc32w(crc, v);
        buf += 4;
        len -= 4;
    }
    while (len--) {
        crc = __crc32b(crc, *buf++);
    }
    return crc ^ 0xFFFFFFFFu;
}
#endif

uint32_t ccrc32_arm(const uint8_t *buf, size_t len) {
#if defined(__aarch64__)
    // Apple Silicon (and every ARMv8.1+ core) implements the CRC32 extension unconditionally.
    return crc32_arm_hw(buf, len);
#else
    return ccrc32_slice8(buf, len);
#endif
}

int ccrc32_arm_active(void) {
#if defined(__aarch64__)
    return 1;
#else
    return 0;
#endif
}

// MARK: - x86-64 hardware (via zlib's PCLMULQDQ)
//
// The SSE4.2 `crc32` instruction computes CRC-32C (Castagnoli, 0x1EDC6F41) — the WRONG polynomial for
// gzip — so it cannot be used. gzip's CRC-32 on x86 needs PCLMULQDQ carry-less-multiply folding; zlib
// already ships a correct, tuned PCLMULQDQ kernel, so we route through it rather than hand-roll
// fragile fold constants for an integrity check.

uint32_t ccrc32_x86(const uint8_t *buf, size_t len) {
#if defined(__x86_64__)
    return ccrc32_zlib(buf, len);
#else
    return ccrc32_slice8(buf, len);
#endif
}

int ccrc32_x86_active(void) {
#if defined(__x86_64__)
    return 1;
#else
    return 0;
#endif
}

// MARK: - Best available

uint32_t ccrc32(const uint8_t *buf, size_t len) {
    // Measured fastest on both Apple Silicon and x86: zlib's crc32. Its PMULL/PCLMULQDQ folding
    // processes multiple independent streams, beating a plain serial __crc32d loop (which is bound by
    // the single-CRC dependency chain) ~1.7x on instructions and ~4x on wall clock at 256 KiB. The
    // bespoke ARM / table backends remain individually selectable via `CRC32.Backend`.
    return ccrc32_zlib(buf, len);
}

const char *ccrc32_backend(void) {
    return "zlib";
}
