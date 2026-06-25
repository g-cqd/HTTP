#include "CHTTPTestMalloc.h"

#if defined(__APPLE__)

#include <pthread.h>
#include <stdlib.h>

/// libsystem_malloc's global logging hook. When non-NULL, libmalloc invokes it on every
/// allocate / free / realloc. Declared here (it lives in a private header) — valid for the
/// test/tooling builds this target serves.
typedef void(httptk_malloc_logger_t)(uint32_t type, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3,
                                      uintptr_t result, uint32_t num_hot_frames_to_skip);
extern httptk_malloc_logger_t *malloc_logger;

/// `MALLOC_LOG_TYPE_ALLOCATE` in libmalloc's stack-logging encoding (a malloc/calloc/realloc-new).
#define HTTPTK_MALLOC_LOG_TYPE_ALLOCATE 2

/// Per-thread measurement state, so each measuring thread counts only its OWN allocations.
///
/// The malloc logger is a process-wide hook fired for every thread, but Swift Testing runs suites in
/// parallel within a single test process — a global counter would tally every concurrent test's
/// allocations and make a measurement non-deterministic. Keying the count to the calling thread
/// (pthread thread-specific data) makes a measurement immune to whatever else is running.
typedef struct {
    uint64_t count;
    int active;
} httptk_state;

static pthread_key_t httptk_key;
static pthread_once_t httptk_key_once = PTHREAD_ONCE_INIT;
static pthread_once_t httptk_install_once = PTHREAD_ONCE_INIT;
static httptk_malloc_logger_t *httptk_prev_logger = 0;

static void httptk_make_key(void) { pthread_key_create(&httptk_key, free); }

static void httptk_counting_logger(uint32_t type, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3,
                                   uintptr_t result, uint32_t num_hot_frames_to_skip) {
    /* pthread_getspecific is async-safe and never allocates; a thread that never measured has no state
       (NULL) and is ignored, so only the measuring thread's allocations are tallied. The hook itself
       must not allocate — it does not. */
    httptk_state *state = pthread_getspecific(httptk_key);
    if (state && state->active && (type & HTTPTK_MALLOC_LOG_TYPE_ALLOCATE)) {
        state->count++;
    }
    /* Chain to whatever hook was already installed (e.g. Instruments) so we don't disrupt it. */
    if (httptk_prev_logger) {
        httptk_prev_logger(type, arg1, arg2, arg3, result, num_hot_frames_to_skip);
    }
}

static void httptk_install(void) {
    httptk_prev_logger = malloc_logger;
    malloc_logger = httptk_counting_logger;
}

int httptk_malloc_counting_available(void) { return 1; }

void httptk_malloc_count_begin(void) {
    pthread_once(&httptk_key_once, httptk_make_key);
    httptk_state *state = pthread_getspecific(httptk_key);
    if (!state) {
        /* First measurement on this thread: allocate its state now, before counting starts, so this
           one-time calloc is never itself measured. */
        state = (httptk_state *)calloc(1, sizeof(httptk_state));
        pthread_setspecific(httptk_key, state);
    }
    /* Install the global hook exactly once and leave it installed (cheap when no thread is active), so
       concurrent begin/end on different threads never race on the shared malloc_logger pointer. */
    pthread_once(&httptk_install_once, httptk_install);
    if (state) {
        state->count = 0;
        state->active = 1;
    }
}

uint64_t httptk_malloc_count_end(void) {
    httptk_state *state = pthread_getspecific(httptk_key);
    if (!state || !state->active) {
        return 0;
    }
    state->active = 0;
    return state->count;
}

#else /* non-Darwin: counting unavailable — a benchmark malloc metric covers Linux CI. */

int httptk_malloc_counting_available(void) { return 0; }
void httptk_malloc_count_begin(void) {}
uint64_t httptk_malloc_count_end(void) { return 0; }

#endif
