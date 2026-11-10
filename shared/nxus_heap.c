/*
 * Nxus inner-heap accounting - console implementation.
 *
 * See nxus_heap.h for the contract and for why mallinfo() alone is not enough.
 * The short version:
 *
 *   total = fake_heap_end - fake_heap_start      (libnx: the 8 MiB inner heap)
 *   arena = mallinfo().arena                     (bytes malloc took from sbrk)
 *   used  = mallinfo().uordblks                  (bytes the program holds)
 *   free  = (total - arena) + mallinfo().fordblks
 *
 * fake_heap_start/fake_heap_end are the same globals switch/source/main.c's
 * __libnx_initheap() assigns, so this measures the heap that actually backs
 * malloc() instead of a second, guessed constant.  Without mallinfo the arena is
 * approximated with sbrk(0).
 *
 * The module is deliberately Switch-only: the host tests compile Switch units
 * without linking the console services, and nxus_heap.h supplies inline 0/no-op
 * fallbacks for them.
 */
#include "nxus_heap.h"

#ifdef __SWITCH__

#include <stddef.h>
#include <stdint.h>

/* devkitPro's newlib has mallinfo(); -DNXUS_HEAP_NO_MALLINFO selects the sbrk(0)
   estimate instead (for a libc that does not provide it). */
#if !defined(NXUS_HEAP_NO_MALLINFO)
#include <malloc.h>
#define NXUS_HEAP_HAS_MALLINFO 1
#endif

#include "nxus_log.h"

/* The arena __libnx_initheap() installs and newlib's sbrk() grows.  Declared
   `extern` exactly as main.c declares them (libsysbase.a defines them), so this is
   the allocator's own view of the heap, not a copy of INNER_HEAP_SIZE. */
extern void *fake_heap_start;
extern void *fake_heap_end;

/* newlib declares sbrk() under its POSIX feature macros, which a strict-ISO build
   hides (the same reason nxus_session.c declares fileno/ftruncate itself). */
extern void *sbrk(ptrdiff_t increment);

typedef struct {
    uint64_t total;   /* 0 = the heap bounds are not published (not measurable) */
    uint64_t used;
    uint64_t free;
} NxusHeapSample;

/* The whole inner heap, or 0 when libnx has not published its bounds (a unit test,
   a port that never calls __libnx_initheap()). */
static uint64_t heapTotalBytes(void) {
    const uintptr_t start = (uintptr_t)fake_heap_start;
    const uintptr_t end   = (uintptr_t)fake_heap_end;
    if (end <= start) return 0;
    return (uint64_t)(end - start);
}

/* Current sbrk() break, or 0 when the call is unavailable/failed. */
static uint64_t heapBreakBytes(void) {
    const uintptr_t start = (uintptr_t)fake_heap_start;
    void *brk = sbrk(0);
    if (brk == (void *)-1 || brk == NULL) return 0;
    const uintptr_t current = (uintptr_t)brk;
    return (current > start) ? (uint64_t)(current - start) : 0;
}

/* One consistent sample: mallinfo() takes newlib's malloc lock and walks the free
   lists, so it must not be called several times per log line just to read two
   fields. */
static void heapSample(NxusHeapSample *out) {
    out->total = heapTotalBytes();
    out->used  = 0;
    out->free  = 0;
    if (out->total == 0) return;   /* nothing measurable */

#if defined(NXUS_HEAP_HAS_MALLINFO)
    const struct mallinfo mi = mallinfo();
    /* arena: bytes taken from the heap so far.  It is NOT the heap size: at boot it
       is a few KiB while 8 MiB are still available.  A libc that leaves the field at
       0 while sbrk() has already grown the heap falls back to the break estimate. */
    uint64_t arena = (uint64_t)mi.arena;
    if (arena == 0) arena = heapBreakBytes();

    out->used = (uint64_t)mi.uordblks;
    /* Untouched remainder of the heap plus the free chunks malloc already holds. */
    out->free = (uint64_t)mi.fordblks;
    if (out->total > arena) out->free += out->total - arena;
#else
    const uint64_t reserved = heapBreakBytes();
    out->used = reserved;                                  /* upper bound */
    out->free = (reserved < out->total) ? out->total - reserved : 0;
#endif

    /* A libc whose bookkeeping disagrees with the published bounds must not make
       the log (or the /3 budget) overflow: clamp both to the heap. */
    if (out->used > out->total) out->used = out->total;
    if (out->free > out->total) out->free = out->total;
}

uint64_t nxusHeapFreeBytes(void) {
    NxusHeapSample s;
    heapSample(&s);
    return s.free;
}

uint64_t nxusHeapUsedBytes(void) {
    NxusHeapSample s;
    heapSample(&s);
    return s.used;
}

void nxusHeapLog(const char *where) {
    const char *tag = (where != NULL) ? where : "?";
    NxusHeapSample s;
    heapSample(&s);
    if (s.total == 0) {
        NXUS_LOG("heap: used=? free=? KiB (%s)", tag);
        return;
    }
    NXUS_LOG("heap: used=%u KiB free=%u KiB (%s)",
             (unsigned)(s.used / NXUS_HEAP_KIB),
             (unsigned)(s.free / NXUS_HEAP_KIB), tag);
}

void nxusHeapLogDebug(const char *where) {
    const char *tag = (where != NULL) ? where : "?";
    NxusHeapSample s;
    heapSample(&s);
    if (s.total == 0) {
        NXUS_LOG_DEBUG("heap: used=? free=? KiB (%s)", tag);
        return;
    }
    NXUS_LOG_DEBUG("heap: used=%u KiB free=%u KiB (%s)",
                   (unsigned)(s.used / NXUS_HEAP_KIB),
                   (unsigned)(s.free / NXUS_HEAP_KIB), tag);
}

void nxusHeapBootReport(void) {
    NxusHeapSample s;
    heapSample(&s);
    if (s.total == 0) {
        NXUS_LOG("heap: free=? KiB (the libnx heap bounds are not published - heap "
                 "accounting is disabled for this build)");
        return;
    }

    NXUS_LOG("heap: free=%u KiB used=%u KiB of %u KiB (boot)",
             (unsigned)(s.free / NXUS_HEAP_KIB),
             (unsigned)(s.used / NXUS_HEAP_KIB),
             (unsigned)(s.total / NXUS_HEAP_KIB));

    if (s.free < NXUS_HEAP_BOOT_WARN_FREE) {
        /* Normally unreachable: a fresh 8 MiB heap has ~8 MiB free.  If it fires,
           something allocated most of the heap before the server started, and the
           next connection/scan will be refused with BUSY/out of memory - exactly
           the symptom this module exists to make visible. */
        NXUS_LOG_ERROR("heap: WARNING free=%u KiB at boot is below the %u KiB headroom - "
                       "a connection (stack+rx buffer) or a scan can fail with BUSY / "
                       "out of memory",
                       (unsigned)(s.free / NXUS_HEAP_KIB),
                       (unsigned)(NXUS_HEAP_BOOT_WARN_FREE / NXUS_HEAP_KIB));
    }
}

#endif /* __SWITCH__ */
