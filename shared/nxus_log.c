#include "nxus_log.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* The ring size now lives in nxus_log.h: the LOG command pages through exactly
   this much, and the server needs the number to size its reply window. */
#define NXUS_LOG_RING_SIZE NXUS_LOG_RING_CAPACITY
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
/* armGetSystemTick() before which a failed open is not retried (see
   logWriteLocked).  Declared here rather than next to its only writer because
   nxusLogInit() clears it: a re-init must not inherit a stale backoff, or the
   first lines after it would be dropped from the SD file for up to 10 s. */
static u64    g_LogRetryAt = 0;
#define NXUS_LOG_FLUSH_BYTES    4096u
#define NXUS_LOG_FLUSH_INTERVAL 500000000ull   /* 500 ms in ns */
#define NXUS_LOG_RETRY_NS       10000000000ull /* 10 s between open retries */

void nxusLogInit(int write_to_sd) {
    /* A second init (__appInit() plus the safety net at the top of main()) used to
       overwrite the open FILE* and leak the descriptor together with whatever was
       still buffered in it.  Flush and close it first - under the existing lock,
       which any prior init has already initialised - and clear the pointer so
       neither this function nor nxusLogExit() can ever close it twice. */
    if (g_LogFile != NULL) {
        mutexLock(&g_LogMutex);
        if (g_LogFile != NULL) {
            fflush(g_LogFile);
            fclose(g_LogFile);
            g_LogFile = NULL;
        }
        mutexUnlock(&g_LogMutex);
    }

    mutexInit(&g_LogMutex);
    g_Ring[0] = 0;
    g_RingLen = 0;
    g_LogToSd = write_to_sd != 0;
    g_LogFile = NULL;
    g_LogBytes = 0;
    /* Nothing is pending on a stream that was just closed, and the backoff of an
       earlier failed open says nothing about the new one. */
    g_LogPending = 0;
    g_LogLastFlush = 0;
    g_LogRetryAt = 0;
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
        /* Evict WHOLE lines: the bytes to give up are rounded forward to the next
           line start, so the ring begins on a line boundary at all times.  A tail
           dump then never starts with half a line, and nxusLogWindow() can treat
           the ring's first byte as a line start (which is what makes the oldest
           page of a backwards walk usable).  At most one extra line (~200 B) is
           given up, and the scan is bounded by the longest line. */
        while (drop < g_RingLen && g_Ring[drop] != '\n') drop++;
        if (drop < g_RingLen) drop++;          /* also drop that newline */
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

size_t nxusLogWindow(char *out, size_t capacity, u32 offset, u32 length) {
    if (out == NULL || capacity == 0) return 0;

    mutexLock(&g_LogMutex);
    const size_t ring_len = g_RingLen;
    if (ring_len == 0 || (size_t)offset >= ring_len) {
        mutexUnlock(&g_LogMutex);
        out[0] = 0;
        return 0;
    }

    /* Newest byte of the window: `offset` bytes back from the end, i.e. the client
       already has everything after it. */
    const size_t end = ring_len - (size_t)offset;
    /* What a complete reply for this poll would carry: the requested length, or
       everything older than the newest byte the client already holds. */
    size_t wanted = length ? (size_t)length : end;
    if (wanted > end) wanted = end;

    /* Reserve room for the truncation note up front, so it can always be prepended
       without pushing the body past `capacity`. */
    size_t span = wanted;
    const size_t note_reserve = (capacity > NXUS_LOG_NOTE_MAX) ? NXUS_LOG_NOTE_MAX : 0;
    const size_t limit = capacity - 1 - note_reserve;
    if (span > limit) span = limit;
    if (span == 0) {
        mutexUnlock(&g_LogMutex);
        out[0] = 0;
        return 0;
    }

    const size_t start = end - span;
    const char *begin = g_Ring + start;

    /* Drop a leading partial line.  ringAppend() keeps the ring line aligned, so
       byte 0 is a line start; any later offset is only a line start when the byte
       before it is the previous line's '\n'. */
    size_t head = 0;
    if (start > 0 && g_Ring[start - 1] != '\n') {
        while (head < span && begin[head] != '\n') head++;
        if (head < span) head++;      /* also leave the partial line's newline out */
        else head = span;             /* no complete line in this window */
    }

    const char *body = begin + head;
    size_t body_len = span - head;
    /* End the reply at the last newline: a trailing half line continues into the
       bytes the client already has, so it belongs to the newer page, not this one. */
    if (body_len > 0 && body[body_len - 1] != '\n') {
        size_t cut = body_len;
        while (cut > 0 && body[cut - 1] != '\n') cut--;
        body_len = cut;
    }
    if (body_len == 0) {
        /* Nothing but fragments: an empty reply is the honest answer, and the caller
           can retry with a bigger window instead of advancing past whole lines. */
        mutexUnlock(&g_LogMutex);
        out[0] = 0;
        return 0;
    }

    size_t pos = 0;
    if (wanted > body_len) {
        const int n = snprintf(out, capacity, "... (truncated %llu bytes)\n",
                               (unsigned long long)(wanted - body_len));
        if (n < 0) {
            mutexUnlock(&g_LogMutex);
            out[0] = 0;
            return 0;
        }
        pos = ((size_t)n >= capacity) ? capacity - 1 : (size_t)n;
    }
    if (pos < capacity - 1) {
        /* The reserve above guarantees this always fits; the clamp only keeps the
           memcpy honest if a caller passes a smaller buffer than documented. */
        const size_t room = capacity - 1 - pos;
        if (body_len > room) body_len = room;
        memcpy(out + pos, body, body_len);
        pos += body_len;
    }
    out[pos] = 0;
    mutexUnlock(&g_LogMutex);
    return pos;
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
