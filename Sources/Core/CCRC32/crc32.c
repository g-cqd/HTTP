//
//  crc32.c
//  CCRC32
//
//  gzip CRC-32 (RFC 1952 §8; reflected polynomial 0xEDB88320). One portable reference (slicing-by-8)
//  plus hardware backends: the ARMv8 CRC32 instructions on aarch64 and our own PCLMULQDQ folding
//  kernel on x86 (x86-64 and i686, CPUID-dispatched). All return the final conditioned checksum and
//  all agree bit-for-bit; `ccrc32_update` is the seeded form of the pick a streaming gzip encoder
//  folds chunk by chunk. Self-contained: no system-library dependency.
//

#include "CCRC32.h"

#include <pthread.h>

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

// Folds `buf[0..<len]` into the *inverted* running state (no initial/final conditioning) through the
// slicing-by-8 tables — the seedable core shared by the one-shot and `ccrc32_update`.
static uint32_t crc32_slice8_fold(uint32_t crc, const uint8_t *buf, size_t len) {
    pthread_once(&kOnce, build_tables);
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
    return crc;
}

uint32_t ccrc32_slice8(const uint8_t *buf, size_t len) {
    return crc32_slice8_fold(0xFFFFFFFFu, buf, len) ^ 0xFFFFFFFFu;
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

// MARK: - ARMv8 CRC32 instructions

#if defined(__aarch64__)
#include <arm_acle.h>
// Folds `buf[0..<len]` into the *inverted* running state (no initial/final conditioning) with the
// ARMv8 CRC32 instructions — the same seedable-core shape as `crc32_slice8_fold`.
__attribute__((target("crc")))
static uint32_t crc32_arm_fold(uint32_t crc, const uint8_t *buf, size_t len) {
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
    return crc;
}
#endif

uint32_t ccrc32_arm(const uint8_t *buf, size_t len) {
#if defined(__aarch64__)
    // Apple Silicon (and every ARMv8.1+ core) implements the CRC32 extension unconditionally.
    return crc32_arm_fold(0xFFFFFFFFu, buf, len) ^ 0xFFFFFFFFu;
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

// MARK: - x86 PCLMULQDQ folding (runtime-dispatched; x86-64 and i686)
//
// Our own carry-less-multiply folding kernel — the technique of Gopal, Ozturk, Guilford, Wolrich,
// Feghali & Dixon, "Fast CRC Computation for Generic Polynomials Using PCLMULQDQ Instruction"
// (Intel white paper 323102, December 2009) — replacing the zlib `crc32()` this file used to borrow
// (the sole system-library link in HTTPCore's graph). The SSE4.2 `crc32` instruction is NOT usable
// here: it computes CRC-32C (Castagnoli, reflected 0x82F63B78), the wrong polynomial for gzip.
//
// The kernel uses only SSE2 vector ops plus PCLMULQDQ — no 64-bit scalar registers — so the same
// source compiles and dispatches correctly in 32-bit mode (`__i386__`). Availability is decided at
// runtime by CPUID (leaf 1: ECX bit 1 = PCLMULQDQ, EDX bit 26 = SSE2; the SSE2 bit matters on
// baseline i686, where SSE2 is not guaranteed); anything short of both folds through the table.

#if defined(__x86_64__) || defined(__i386__)

#include <cpuid.h>
#include <immintrin.h>

static int kHasPCLMUL = 0;
static pthread_once_t kCPUIDOnce = PTHREAD_ONCE_INIT;

static void detect_x86_features(void) {
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx) == 0) {
        return;  // CPUID leaf 1 unavailable (pre-Pentium class) — table path.
    }
    kHasPCLMUL = ((ecx & (1u << 1)) != 0)     // PCLMULQDQ
              && ((edx & (1u << 26)) != 0);   // SSE2 (not baseline on i686)
}

static int x86_has_pclmul(void) {
    pthread_once(&kCPUIDOnce, detect_x86_features);
    return kHasPCLMUL;
}

// Bit-reflected-domain constants, each `reflect32(x^t mod P) << 1` for P = 0x104C11DB7 (the +-32
// offsets against the nominal fold distances fall out of PCLMULQDQ's 64x64->127-bit product sitting
// unshifted in the 128-bit lane of a reflected-domain accumulator). Derivation cross-checked against
// the white paper's appendix values and a bit-exact model of this whole kernel validated against an
// independent CRC-32 for one-shot and seeded folds across every loop-stage boundary.
static const uint64_t kFoldBy4[2] __attribute__((aligned(16))) = {
    0x0154442BD4,  // reflect32(x^544 mod P) << 1 — 512-bit stride, low qword
    0x01C6E41596,  // reflect32(x^480 mod P) << 1 — 512-bit stride, high qword
};
static const uint64_t kFoldBy1[2] __attribute__((aligned(16))) = {
    0x01751997D0,  // reflect32(x^160 mod P) << 1 — 128-bit stride, low qword
    0x00CCAA009E,  // reflect32(x^96 mod P) << 1  — 128-bit stride, high qword (also folds 128->64)
};
static const uint64_t kFold64[2] __attribute__((aligned(16))) = {
    0x0163CD6124,  // reflect32(x^64 mod P) << 1  — folds the final 96 bits to 64
    0,
};
static const uint64_t kBarrett[2] __attribute__((aligned(16))) = {
    0x01DB710641,  // P' = reflect33(P)
    0x01F7011641,  // mu = reflect33(floor(x^64 / P))
};

// One 128-bit fold step: `x` folded forward across `next` by the stride `k` encodes.
__attribute__((always_inline, target("sse2,pclmul")))
static inline __m128i crc32_fold_step(__m128i x, __m128i next, __m128i k) {
    __m128i lo = _mm_clmulepi64_si128(x, k, 0x00);
    __m128i hi = _mm_clmulepi64_si128(x, k, 0x11);
    return _mm_xor_si128(_mm_xor_si128(lo, hi), next);
}

// Folds `buf[0..<len]` (len a multiple of 16, at least 64) into the *inverted* running state — the
// same seedable-core shape as `crc32_slice8_fold` / `crc32_arm_fold`. Four independent 128-bit
// accumulators stream past the single-CRC dependency chain; the tail folds them back to one, reduces
// 128 -> 64 -> 32, and finishes with a Barrett reduction.
__attribute__((target("sse2,pclmul")))
static uint32_t crc32_pclmul_fold(uint32_t crc, const uint8_t *buf, size_t len) {
    const __m128i k4 = _mm_load_si128((const __m128i *)(const void *)kFoldBy4);
    const __m128i k1 = _mm_load_si128((const __m128i *)(const void *)kFoldBy1);
    __m128i x1 = _mm_loadu_si128((const __m128i *)(const void *)(buf + 0));
    __m128i x2 = _mm_loadu_si128((const __m128i *)(const void *)(buf + 16));
    __m128i x3 = _mm_loadu_si128((const __m128i *)(const void *)(buf + 32));
    __m128i x4 = _mm_loadu_si128((const __m128i *)(const void *)(buf + 48));
    // The seed folds into the low 32 bits: reflected domain, so low bits are the earliest octets.
    x1 = _mm_xor_si128(x1, _mm_cvtsi32_si128((int)crc));
    buf += 64;
    len -= 64;
    while (len >= 64) {  // fold-by-4: 64-byte stride
        x1 = crc32_fold_step(x1, _mm_loadu_si128((const __m128i *)(const void *)(buf + 0)), k4);
        x2 = crc32_fold_step(x2, _mm_loadu_si128((const __m128i *)(const void *)(buf + 16)), k4);
        x3 = crc32_fold_step(x3, _mm_loadu_si128((const __m128i *)(const void *)(buf + 32)), k4);
        x4 = crc32_fold_step(x4, _mm_loadu_si128((const __m128i *)(const void *)(buf + 48)), k4);
        buf += 64;
        len -= 64;
    }
    // Fold the four accumulators back into one (128-bit stride), then any remaining 16-byte blocks.
    x1 = crc32_fold_step(x1, x2, k1);
    x1 = crc32_fold_step(x1, x3, k1);
    x1 = crc32_fold_step(x1, x4, k1);
    while (len >= 16) {
        x1 = crc32_fold_step(x1, _mm_loadu_si128((const __m128i *)(const void *)buf), k1);
        buf += 16;
        len -= 16;
    }
    // Reduce 128 -> 64: fold the low qword across the high (x^96, the high qword of kFoldBy1).
    __m128i t = _mm_clmulepi64_si128(x1, k1, 0x10);
    x1 = _mm_xor_si128(_mm_srli_si128(x1, 8), t);
    // Reduce 96 -> 64: fold the low dword up by x^64.
    const __m128i mask32 = _mm_set_epi32(0, 0, 0, -1);
    const __m128i k5 = _mm_load_si128((const __m128i *)(const void *)kFold64);
    t = _mm_srli_si128(x1, 4);
    x1 = _mm_and_si128(x1, mask32);
    x1 = _mm_clmulepi64_si128(x1, k5, 0x00);
    x1 = _mm_xor_si128(x1, t);
    // Barrett reduction 64 -> 32: q = (lo32 * mu), state ^= q_lo32 * P'.
    const __m128i br = _mm_load_si128((const __m128i *)(const void *)kBarrett);
    t = _mm_and_si128(x1, mask32);
    t = _mm_clmulepi64_si128(t, br, 0x10);
    t = _mm_and_si128(t, mask32);
    t = _mm_clmulepi64_si128(t, br, 0x00);
    x1 = _mm_xor_si128(x1, t);
    // The reduced (still inverted) state lands in dword 1.
    return (uint32_t)_mm_cvtsi128_si32(_mm_srli_si128(x1, 4));
}

// The x86 seedable core: PCLMULQDQ over whole 16-byte blocks when the CPU has it and the input is
// big enough to amortize the reduction; the slicing-by-8 table for the remainder and everything else.
static uint32_t crc32_x86_fold(uint32_t crc, const uint8_t *buf, size_t len) {
    if (len >= 64 && x86_has_pclmul()) {
        size_t vector_len = len & ~(size_t)15;
        crc = crc32_pclmul_fold(crc, buf, vector_len);
        buf += vector_len;
        len -= vector_len;
    }
    return crc32_slice8_fold(crc, buf, len);
}

#endif  /* __x86_64__ || __i386__ */

uint32_t ccrc32_x86(const uint8_t *buf, size_t len) {
#if defined(__x86_64__) || defined(__i386__)
    return crc32_x86_fold(0xFFFFFFFFu, buf, len) ^ 0xFFFFFFFFu;
#else
    return ccrc32_slice8(buf, len);
#endif
}

int ccrc32_x86_active(void) {
#if defined(__x86_64__) || defined(__i386__)
    return x86_has_pclmul();
#else
    return 0;
#endif
}

// MARK: - Best available

uint32_t ccrc32(const uint8_t *buf, size_t len) {
#if defined(__aarch64__)
    // Serial __crc32d, ~8 B/cycle. The zlib borrow's PMULL folding measured ~4x faster at 256 KiB
    // (multiple independent streams past the single-CRC dependency chain); it went with the
    // system-library link — a knowing trade for a checksum folded once per gzip member. The reclaim
    // path, should profiles ever demand it, is a multi-stream __crc32d/PMULL kernel here.
    return ccrc32_arm(buf, len);
#elif defined(__x86_64__) || defined(__i386__)
    return ccrc32_x86(buf, len);
#else
    return ccrc32_slice8(buf, len);
#endif
}

uint32_t ccrc32_update(uint32_t crc, const uint8_t *buf, size_t len) {
    // The running value carries the same final conditioning as the one-shots, so seeding is
    // un-conditioning the previous return; an empty/NULL chunk folds nothing.
    if (buf == NULL || len == 0) {
        return crc;
    }
#if defined(__aarch64__)
    return crc32_arm_fold(crc ^ 0xFFFFFFFFu, buf, len) ^ 0xFFFFFFFFu;
#elif defined(__x86_64__) || defined(__i386__)
    return crc32_x86_fold(crc ^ 0xFFFFFFFFu, buf, len) ^ 0xFFFFFFFFu;
#else
    return crc32_slice8_fold(crc ^ 0xFFFFFFFFu, buf, len) ^ 0xFFFFFFFFu;
#endif
}

const char *ccrc32_backend(void) {
#if defined(__aarch64__)
    return "arm-crc32";
#elif defined(__x86_64__) || defined(__i386__)
    return x86_has_pclmul() ? "pclmul" : "slice8";
#else
    return "slice8";
#endif
}
