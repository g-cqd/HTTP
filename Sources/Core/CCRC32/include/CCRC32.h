//
//  CCRC32.h
//  CCRC32
//
//  Hardware/SWAR backends for the gzip CRC-32 (RFC 1952 §8; reflected polynomial 0xEDB88320), behind
//  the pure-Swift `CRC32` facade. Every function returns the *final* checksum (the value gzip appends)
//  of `buf[0..<len]`, and all agree bit-for-bit with the portable reference; the CPU-specific ones fall
//  back to the table when their feature is unavailable. All are one-shots except `ccrc32_update`, the
//  seeded form a streaming encoder folds chunk by chunk.
//

#ifndef CCRC32_H
#define CCRC32_H

#include <stddef.h>
#include <stdint.h>

/// The fastest backend available on this CPU (ARM CRC32 / zlib-on-x86 / slicing-by-8 table).
uint32_t ccrc32(const uint8_t *buf, size_t len);

/// Folds `buf[0..<len]` into a running checksum and returns the checksum *so far*.
///
/// The seeded form of ``ccrc32``: start at 0, feed each chunk in order, and the last return is the
/// value gzip appends — so `ccrc32_update(0, buf, len) == ccrc32(buf, len)`. A streaming encoder
/// cannot hold its payload to checksum it at the end, which is the only reason this exists. The
/// running value carries the same final conditioning as the one-shots (not the inverted intermediate),
/// so any prefix of the fold is itself a valid checksum of that prefix.
uint32_t ccrc32_update(uint32_t crc, const uint8_t *buf, size_t len);

/// Portable slicing-by-8 table (always available) — the cross-check reference.
uint32_t ccrc32_slice8(const uint8_t *buf, size_t len);

/// The naive one-octet-at-a-time table (the original algorithm) — the comparison baseline.
uint32_t ccrc32_slice1(const uint8_t *buf, size_t len);

/// zlib's `crc32()` — correct polynomial, internally hardware-accelerated (PCLMULQDQ on x86).
uint32_t ccrc32_zlib(const uint8_t *buf, size_t len);

/// ARMv8 CRC32 instructions (`__crc32*`); falls back to the table off aarch64.
uint32_t ccrc32_arm(const uint8_t *buf, size_t len);

/// x86-64 hardware path: zlib's PCLMULQDQ-accelerated `crc32` (the SSE4.2 `crc32` instruction is the
/// CRC-32C/Castagnoli polynomial, which is *wrong* for gzip); falls back to the table off x86-64.
uint32_t ccrc32_x86(const uint8_t *buf, size_t len);

/// Whether a genuine hardware backend is active for this arch (1) or it fell back to the table (0).
int ccrc32_arm_active(void);
int ccrc32_x86_active(void);

/// A human-readable name of the backend ``ccrc32`` selects on this build (for benchmarks / logging).
const char *ccrc32_backend(void);

#endif /* CCRC32_H */
