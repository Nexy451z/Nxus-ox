/*
 * Nxus inner-heap accounting.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * The sysmodule allocates everything from one 8 MiB newlib heap (switch/source/
 * main.c: INNER_HEAP_SIZE, installed by __libnx_initheap()).  The receive buffers
 * of up to four client connections, the scan engine, the hit list, the snapshots
 * and the Unknown-scan baseline store all compete for it - and until now a refused
 * malloc was only visible indirectly: the connection was answered BUSY, a scan
 * reported "0 candidates", or a client simply could not connect.  Nothing said
 * HOW MUCH was left, so "nxus is out of heap at boot" could not be told apart from
 * "the PC did not connect".
 *
 * This module answers two questions and one policy:
 *
 *   nxusHeapFreeBytes()  bytes the allocator can still hand out,
 *   nxusHeapUsedBytes()  bytes it reports as allocated,
 *   nxusHeapBaselineRamLimit()  how much of that the Unknown-scan baseline store
 *                        may take for itself (min(NXUS_HEAP_BASELINE_RAM_MAX,
 *                        free / NXUS_HEAP_BASELINE_FREE_DIVISOR)).
 *
 * MEASUREMENT (console)
 * ---------------------
 * newlib's mallinfo() describes the sbrk()-backed arena that libnx publishes
 * through fake_heap_start/fake_heap_end:
 *
 *   arena    bytes malloc has taken from the heap      (arena grows via sbrk)
 *   uordblks bytes the program currently holds          (chunk headers included)
 *   fordblks free chunks inside the arena
 *
 * free is therefore "what nobody has touched yet" plus "what malloc already holds
 * and can reuse":
 *
 *   free = (heap_end - heap_start - arena) + fordblks
 *
 * mallinfo() alone is NOT that number: at boot the arena is a few KiB, while the
 * heap is 8 MiB, so its fordblks would report "almost no memory left" for a module
 * that has barely allocated.  Without mallinfo (a port built with
 * -DNXUS_HEAP_NO_MALLINFO) the same split is estimated from sbrk(0); `used` is
 * then the whole reservation, i.e. an upper bound.
 *
 * Both numbers are approximations, good enough for a log line and a 1/3 budget.
 * They describe different things (what the program holds vs. what the allocator can
 * still hand out), so do not use "used + free" as a byte-exact heap size:
 * newlib's mallinfo happens to make them complementary, but another libc may
 * account chunk headers differently.
 *
 * HOST
 * ----
 * tests/ compile Switch translation units (nxus_session.c) on the host, where no
 * sysmodule heap exists.  The host fallbacks below return 0 / log nothing and are
 * `static inline`, so a test that includes a shipped .c does not have to link
 * nxus_heap.c.  A 0 measurement is meaningful: it tells callers "nothing is known",
 * which the policy helpers treat as "no RAM budget" (see nxus_heapBaselineFitsRam)
 * and the boot report prints as free=? instead of inventing a number.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

/* 1 KiB, used to turn the byte counts into the numbers the log prints. */
#define NXUS_HEAP_KIB (1024ull)

/* Historic ceiling for the RAM-backed baseline store (nxus_session.c): the whole
   scoped range is held in one block instead of streamed to the card.  It is a
   convenience, not a requirement - the SD stream is the fallback - so it must never
   crowd out the hit list, the scan buffers or a connection. */
#define NXUS_HEAP_BASELINE_RAM_MAX (4ull * 1024ull * 1024ull)

/* The live baseline may take at most this fraction of the CURRENTLY free heap.
   A third keeps two thirds for the hit list (~3.0 MiB budget), the scan buffers
   (up to 2 MiB) and the connection receive buffers/stacks, so arming the baseline
   cannot be the allocation that leaves the next connection without a buffer. */
#define NXUS_HEAP_BASELINE_FREE_DIVISOR (3ull)

/* Below this much free heap the boot report emits a warning line: a connection
   needs NXUS_NET_CLIENT_STACK_SIZE + NXUS_NET_RX_IDLE_SIZE (56 KiB) and a scan
   needs its chunk buffer, so a boot with less than this headroom is already a
   module that will refuse work. */
#define NXUS_HEAP_BOOT_WARN_FREE (512ull * 1024ull)

/* Largest RAM baseline the session may allocate with `heap_free_bytes` free:
   min(NXUS_HEAP_BASELINE_RAM_MAX, free / NXUS_HEAP_BASELINE_FREE_DIVISOR).
   A 0 (unmeasurable or completely exhausted) heap yields 0, which sends the
   caller to the SD stream instead of into a doomed malloc. */
static inline uint64_t nxusHeapBaselineRamLimit(uint64_t heap_free_bytes) {
    const uint64_t share = heap_free_bytes / NXUS_HEAP_BASELINE_FREE_DIVISOR;
    return (share < NXUS_HEAP_BASELINE_RAM_MAX) ? share : NXUS_HEAP_BASELINE_RAM_MAX;
}

/* May a `bytes`-sized baseline store live in RAM right now?  `bytes == 0` is never
   a store (nothing to keep), and a 0 free measurement never fits anything. */
static inline bool nxusHeapBaselineFitsRam(uint64_t heap_free_bytes, uint64_t bytes) {
    if (bytes == 0) return false;
    return bytes <= nxusHeapBaselineRamLimit(heap_free_bytes);
}

#ifdef __SWITCH__

/* Bytes the allocator can still hand out (0 when the heap is not measurable). */
uint64_t nxusHeapFreeBytes(void);
/* Bytes newlib reports as allocated (chunk headers included). */
uint64_t nxusHeapUsedBytes(void);

/* Full accounting line, greppable as "heap: used=... free=... KiB".
 * nxusHeapLog() writes at info level (state a user should see: a refused
 * allocation, a degraded fallback), nxusHeapLogDebug() at debug level (one line per
 * measurement point while the module behaves normally). */
void nxusHeapLog(const char *where);
void nxusHeapLogDebug(const char *where);

/* One line at boot - "heap: free=... KiB" - plus a warning when the free heap is
 * below NXUS_HEAP_BOOT_WARN_FREE.  Called once from nxusSessionInit(). */
void nxusHeapBootReport(void);

#else /* host / non-libnx build: no sysmodule heap to measure (see HOST above) */

static inline uint64_t nxusHeapFreeBytes(void) { return 0; }
static inline uint64_t nxusHeapUsedBytes(void) { return 0; }
static inline void nxusHeapLog(const char *where) { (void)where; }
static inline void nxusHeapLogDebug(const char *where) { (void)where; }
static inline void nxusHeapBootReport(void) {}

#endif

/* Free heap in KiB, for the "(free=... KiB)" tail of an out-of-memory log line.
   Inline over nxusHeapFreeBytes() so a host build without the .c module still
   compiles (and prints 0). */
static inline uint32_t nxusHeapFreeKiB(void) {
    return (uint32_t)(nxusHeapFreeBytes() / NXUS_HEAP_KIB);
}
