#include "nxus_log.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define NXUS_LOG_RING_SIZE 16384
/* One assembled line: the uptime prefix plus the caller's message.  The old 512
   bytes were sized for the message alone; the prefix eats up to ~16 of them and
   the longest existing format (the debug "set break" line) is already ~200. */
#define NXUS_LOG_LINE_SIZE 1024
#define NXUS_LOG_PATH      "sdmc:/nxus/nxus.log"
#define NXUS_LOG_OLD_PATH  "sdmc:/nxus/nxus.log.1"
/* Rotate instead of growing without bound: a sysmodule that runs for days (and
   logs a line per hit burst) must not fill the SD card.  256 KiB is ~10x the
   useful history and one rename is far cheaper than a full disk. */
#define NXUS_LOG_MAX_BYTES (256u * 1024u)

static char   g_Ring[NXUS_LOG_RING_SIZE];
static size_t g_RingLen = 0;      /* bytes used, buffer is always NUL terminated */
static Mutex  g_LogMutex;
static bool   g_LogToSd = false;
/* Verbosity threshold (see nxus_log.h).  Not reset by nxusLogInit(): the level is
   runtime policy, not buffer state, and the boot path may call init twice.  An
   aligned u32 store/load is atomic on the target, so no lock is taken to read it. */
static u32    g_LogLevel = NXUS_LOG_LEVEL_INFO;
/* Keeping the file open turns one fopen+fwrite+fclose (three SD round trips) per
   line into a single buffered write plus fflush.  The flush keeps the crash
   diagnostics intact - an unflushed buffer would lose exactly the lines that
   explain a hang. */
static FILE  *g_LogFile = NULL;
static u64    g_LogBytes = 0;
/* Unflushed bytes + the last flush time.  fflush() per line turned every log line
   into an SD write; a 4 KiB / 500 ms policy keeps the data loss window short for
   crash diagnostics (nxusLogExit flushes) while cutting the write count by ~97%. */
static u32    g_LogPending = 0;
static u64    g_LogLastFlush = 0;
#define NXUS_LOG_FLUSH_BYTES    4096u
#define NXUS_LOG_FLUSH_INTERVAL 500000000ull   /* 500 ms in ns */
#define NXUS_LOG_RETRY_NS       10000000000ull /* 10 s between open retries */

void nxusLogInit(int write_to_sd) {
    mutexInit(&g_LogMutex);
    g_Ring[0] = 0;
    g_RingLen = 0;
    g_LogToSd = write_to_sd != 0;
    g_LogFile = NULL;
    g_LogBytes = 0;
}

void nxusLogSetLevel(u32 level) {
    if (level > NXUS_LOG_LEVEL_DEBUG) level = NXUS_LOG_LEVEL_DEBUG;
    g_LogLevel = level;
}

u32 nxusLogGetLevel(void) {
    return g_LogLevel;
}

void nxusLogExit(void) {
    mutexLock(&g_LogMutex);
    if (g_LogFile != NULL) {
        fflush(g_LogFile);
        fclose(g_LogFile);
        g_LogFile = NULL;
    }
    mutexUnlock(&g_LogMutex);
}

/* Open (or reopen after a rotation) the append stream and learn its size. */
static bool logOpenLocked(const char *mode) {
    if (g_LogFile != NULL) { fclose(g_LogFile); g_LogFile = NULL; }
    g_LogFile = fopen(NXUS_LOG_PATH, mode);
    g_LogBytes = 0;
    if (g_LogFile == NULL) return false;
    if (mode[0] == 'a') {
        if (fseek(g_LogFile, 0, SEEK_END) == 0) {
            long size = ftell(g_LogFile);
            g_LogBytes = (size > 0) ? (u64)size : 0;
        }
    }
    return true;
}

static void logRotateLocked(void) {
    if (g_LogFile != NULL) { fclose(g_LogFile); g_LogFile = NULL; }
    remove(NXUS_LOG_OLD_PATH);
    /* A failed rename (e.g. the old copy could not be removed) still must not let
       the log grow forever, so fall through to truncation. */
    if (rename(NXUS_LOG_PATH, NXUS_LOG_OLD_PATH) != 0) {
        (void)logOpenLocked("wb");
        return;
    }
    (void)logOpenLocked("ab");
}

static u64 g_LogRetryAt = 0;

static void logWriteLocked(const char *line, size_t len) {
    if (!g_LogToSd) return;
    if (g_LogFile == NULL) {
        /* A missing/unwritable sdmc:/nxus turned every single log line into an
           fopen()+fclose() (measured ~57 us per call).  Back off for 10 s after a
           failed open so logging stays cheap on a read-only or full SD card. */
        const u64 now = armGetSystemTick();
        if (g_LogRetryAt != 0 && now < g_LogRetryAt) return;
        if (!logOpenLocked("ab")) {
            g_LogRetryAt = now + armNsToTicks(NXUS_LOG_RETRY_NS);
            return;
        }
        g_LogRetryAt = 0;
    }
    if (g_LogBytes >= NXUS_LOG_MAX_BYTES) {
        logRotateLocked();
        if (g_LogFile == NULL) return;
    }
    if (fwrite(line, 1, len, g_LogFile) == len) {
        g_LogBytes += len;
        g_LogPending += (u32)len;
        const u64 now = armGetSystemTick();
        if (g_LogPending >= NXUS_LOG_FLUSH_BYTES || g_LogLastFlush == 0 ||
            armTicksToNs(now - g_LogLastFlush) >= NXUS_LOG_FLUSH_INTERVAL) {
            fflush(g_LogFile);
            g_LogPending = 0;
            g_LogLastFlush = now;
        }
    }
}

static void ringAppend(const char *text, size_t len) {
    if (len >= NXUS_LOG_RING_SIZE) {
        text += (len - NXUS_LOG_RING_SIZE + 1);
        len = NXUS_LOG_RING_SIZE - 1;
    }
    if (g_RingLen + len >= NXUS_LOG_RING_SIZE) {
        size_t drop = g_RingLen + len - (NXUS_LOG_RING_SIZE - 1);
        memmove(g_Ring, g_Ring + drop, g_RingLen - drop);
        g_RingLen -= drop;
    }
    memcpy(g_Ring + g_RingLen, text, len);
    g_RingLen += len;
    g_Ring[g_RingLen] = 0;
}

/* Uptime prefix, fixed width so a tail dump stays column aligned:
   "[  12345.678] " - seconds in a 7-wide field, milliseconds zero padded, then
   one space.  Past 9 999 999 s (~115 days) the field just grows by a digit; a
   sysmodule is never up that long, and truncating the number would be worse than
   a shifted colon.  Integer math on purpose: "%f" would pull the soft-float
   formatter (and the FPU context) into every single log line. */
static size_t logPrefix(char *out, size_t capacity) {
    const u64 ns = armTicksToNs(armGetSystemTick());
    int n = snprintf(out, capacity, "[%7llu.%03llu] ",
                     (unsigned long long)(ns / 1000000000ull),
                     (unsigned long long)((ns / 1000000ull) % 1000ull));
    if (n < 0) {
        out[0] = 0;
        return 0;
    }
    if ((size_t)n >= capacity) n = (int)capacity - 1;
    return (size_t)n;
}

/* Assemble "<prefix><message>\n" into one buffer and hand the finished line to
   the ring buffer and the SD stream.  The prefix is written first and the message
   is formatted into the rest of the same buffer, so a line that does not fit is
   truncated once (by vsnprintf) instead of via an extra copy. */
static void logEmit(const char *fmt, va_list ap) {
    char line[NXUS_LOG_LINE_SIZE];
    const size_t prefix = logPrefix(line, sizeof(line));
    const size_t room = sizeof(line) - prefix;   /* includes the NUL slot */

    int n = vsnprintf(line + prefix, room, fmt, ap);
    if (n < 0) return;
    size_t len = (size_t)n;
    if (len > room - 2) len = room - 2;          /* keep room for '\n' + NUL */

    size_t pos = prefix + len;
    line[pos++] = '\n';
    line[pos] = 0;

    mutexLock(&g_LogMutex);
    ringAppend(line, pos);
    logWriteLocked(line, pos);
    mutexUnlock(&g_LogMutex);
}

void nxusLogWrite(const char *fmt, ...) {
    /* Checked before formatting: a suppressed line costs one call, no vsnprintf. */
    if (g_LogLevel < NXUS_LOG_LEVEL_INFO) return;
    va_list ap;
    va_start(ap, fmt);
    logEmit(fmt, ap);
    va_end(ap);
}

void nxusLogWriteDebug(const char *fmt, ...) {
    if (g_LogLevel < NXUS_LOG_LEVEL_DEBUG) return;
    va_list ap;
    va_start(ap, fmt);
    logEmit(fmt, ap);
    va_end(ap);
}

void nxusLogWriteError(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    logEmit(fmt, ap);
    va_end(ap);
}

void nxusLogEvent(u32 event_id, const char *fmt, ...) {
    char detail[384];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(detail, sizeof(detail), fmt, ap);
    va_end(ap);
    nxusLogWrite("[event 0x%04X] %s", (unsigned)event_id, detail);
}

size_t nxusLogTail(char *out, size_t capacity) {
    if (out == NULL || capacity == 0) return 0;
    mutexLock(&g_LogMutex);
    size_t len = g_RingLen;
    if (len > capacity - 1) len = capacity - 1;
    memcpy(out, g_Ring + (g_RingLen - len), len);
    out[len] = 0;
    mutexUnlock(&g_LogMutex);
    return len;
}

void nxusLogFlush(void) {
    mutexLock(&g_LogMutex);
    if (g_LogFile != NULL) {
        fflush(g_LogFile);
        g_LogPending = 0;
        g_LogLastFlush = armGetSystemTick();
    }
    mutexUnlock(&g_LogMutex);
}
