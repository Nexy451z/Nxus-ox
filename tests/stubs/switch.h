/*
 * Minimal host stand-in for libnx's <switch.h>.
 *
 * ONLY tests/test_session_view.c uses this (run_tests.sh puts this directory
 * first on the include path for that single test), because nxus_session.c is a
 * Switch unit that links straight against libnx: it includes <switch.h>, takes a
 * Mutex, spawns a Thread and reads the system tick.  Supplying those few types and
 * calls here lets the test compile the SHIPPED nxus_session.c - the pin/retire
 * machinery under test is the real code, not a copy of it.
 *
 * The Result values are arbitrary: nothing under test branches on a specific
 * libnx error code, they are only compared against 0.
 */
#pragma once

#include <pthread.h>
#include <stdalign.h>   /* alignas(): libnx's switch.h pulls it in indirectly */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;

typedef u32 Result;
typedef u32 Handle;

#define R_SUCCEEDED(res) ((res) == 0)
#define R_FAILED(res)    ((res) != 0)

enum { Module_Libnx = 345 };
enum {
    LibnxError_NotInitialized = 1,
    LibnxError_OutOfMemory    = 2,
    LibnxError_BadInput       = 4,
};

#define MAKERESULT(module, description)                                     \
    ((Result)(0x80000000u | (((u32)(module) & 0x1FFu) << 9) |                \
              ((u32)(description) & 0x1FFu)))

/* ---- mutex ---- */
typedef struct {
    pthread_mutex_t mutex;
} Mutex;

static inline void mutexInit(Mutex *m) { pthread_mutex_init(&m->mutex, NULL); }
static inline void mutexLock(Mutex *m) { pthread_mutex_lock(&m->mutex); }
static inline void mutexUnlock(Mutex *m) { pthread_mutex_unlock(&m->mutex); }

/* ---- threads ---- */
typedef void (*ThreadFunc)(void *);

typedef struct {
    int unused;
} Thread;

/* The view tests never run a scan worker, and a real worker would need dmnt.
   Reporting failure keeps an accidental startJob() from running the engine
   against the stubs below. */
static inline Result threadCreate(Thread *t, ThreadFunc entry, void *arg, void *stack_mem,
                                 size_t stack_sz, int prio, int cpuid) {
    (void)t; (void)entry; (void)arg; (void)stack_mem; (void)stack_sz; (void)prio; (void)cpuid;
    return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
}
static inline void threadStart(Thread *t) { (void)t; }
static inline void threadWaitForExit(Thread *t) { (void)t; }
static inline void threadClose(Thread *t) { (void)t; }

/* ---- time ---- */
static inline u64 armGetSystemTick(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (u64)ts.tv_sec * 1000000000ull + (u64)ts.tv_nsec;   /* already ns */
}
static inline u64 armTicksToNs(u64 ticks) { return ticks; }
static inline void svcSleepThread(s64 ns) { (void)ns; }
