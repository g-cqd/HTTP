#ifndef CHTTPTEST_MALLOC_H
#define CHTTPTEST_MALLOC_H

#include <stdint.h>

/// Process-wide heap-allocation counting for test perf guards (HTTPTestSupport's `expectAllocations`).
///
/// On Darwin this installs libmalloc's logging hook (`malloc_logger`) — a tooling seam Instruments
/// uses. It is enabled only in TEST / tooling builds and never ships in an App-Store binary, so the
/// private symbol is acceptable here. On other platforms the counter is a no-op and
/// `httptk_malloc_counting_available()` returns 0, so the Swift oracle degrades gracefully.
///
/// Measurement is process-wide: count a SYNCHRONOUS region with no concurrent allocation for an
/// accurate delta. Not re-entrant across threads (toggle from one thread around the measured region).

/// 1 when allocation counting is available on this platform (Darwin), 0 otherwise.
int httptk_malloc_counting_available(void);

/// Reset the counters and install the counting hook (chaining to any previously installed hook).
void httptk_malloc_count_begin(void);

/// Restore the previous hook and return the number of allocations observed since `begin`.
uint64_t httptk_malloc_count_end(void);

/// Stop counting, reporting the allocation count in `count` and the requested octets in `bytes`.
///
/// Either pointer may be NULL. The octet total is *cumulative requested size*, not peak residency:
/// a grow-copy-free loop is charged for every intermediate buffer. That is the useful shape for the
/// guard it serves — a routine that sizes one buffer straight to a hard cap and one that grows
/// geometrically to a much smaller final size are indistinguishable by allocation *count*, and differ
/// by orders of magnitude in octets.
void httptk_malloc_count_stop(uint64_t *count, uint64_t *bytes);

#endif /* CHTTPTEST_MALLOC_H */
