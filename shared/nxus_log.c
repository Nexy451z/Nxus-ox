#include "nxus_log.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define NXUS_LOG_RING_SIZE 16384
#define NXUS_LOG_PATH      "sdmc:/nxus/nxus.log"

static char   g_Ring[NXUS_LOG_RING_SIZE];
static size_t g_RingLen = 0;      /* bytes used, buffer is always NUL terminated */
static Mutex  g_LogMutex;
static bool   g_LogToSd = false;

void nxusLogInit(int write_to_sd) {
    mutexInit(&g_LogMutex);
    g_Ring[0] = 0;
    g_RingLen = 0;
    g_LogToSd = write_to_sd != 0;
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

void nxusLogWrite(const char *fmt, ...) {
    char line[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(line, sizeof(line) - 2, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if ((size_t)n > sizeof(line) - 2) n = (int)sizeof(line) - 2;
    line[n++] = '\n';
    line[n] = 0;

    mutexLock(&g_LogMutex);
    ringAppend(line, (size_t)n);

    if (g_LogToSd) {
        FILE *f = fopen(NXUS_LOG_PATH, "ab");
        if (f != NULL) {
            fwrite(line, 1, (size_t)n, f);
            fclose(f);
        }
    }
    mutexUnlock(&g_LogMutex);
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
    /* the SD file is opened/closed per line, so there is nothing buffered */
}
