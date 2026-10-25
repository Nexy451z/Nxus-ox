/* Nxus logging: in-memory ring buffer (readable over the protocol) + SD file. */
#pragma once

#include <switch.h>
#include <stddef.h>

/* Verbosity threshold for nxusLogSetLevel().  A message is written when its own
   level is <= the current one, so 0 keeps only errors, 1 adds info (default) and
   2 adds debug. */
#define NXUS_LOG_LEVEL_ERROR 0u
#define NXUS_LOG_LEVEL_INFO  1u
#define NXUS_LOG_LEVEL_DEBUG 2u

void nxusLogInit(int write_to_sd);
/* Flush and close the SD stream (it stays open for the whole run). */
void nxusLogExit(void);

/* info line: written while the level is >= NXUS_LOG_LEVEL_INFO.  The signature is
   unchanged, so every existing NXUS_LOG()/NXUS_RESULT() call keeps working. */
void nxusLogWrite(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
/* debug line: written only at NXUS_LOG_LEVEL_DEBUG.  The level is checked before
   the arguments are formatted, so a demoted hot-path line costs one call. */
void nxusLogWriteDebug(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
/* error line: always written, whatever the level is. */
void nxusLogWriteError(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

void nxusLogEvent(u32 event_id, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

/* 0 = error, 1 = info (default), 2 = debug.  Values above 2 are clamped to 2.
   Safe to call from any thread while other threads are logging. */
void nxusLogSetLevel(u32 level);
u32  nxusLogGetLevel(void);

/* Copy the tail of the ring buffer into out (NUL terminated). Returns bytes written. */
size_t nxusLogTail(char *out, size_t capacity);

/* Flush the SD file (no-op when SD logging is disabled). */
void nxusLogFlush(void);

/* Every line already carries the "[  12345.678] " uptime prefix; the level only
   decides whether the line is produced at all. */
#define NXUS_LOG(...)        nxusLogWrite(__VA_ARGS__)
#define NXUS_LOG_DEBUG(...)  nxusLogWriteDebug(__VA_ARGS__)
#define NXUS_LOG_ERROR(...)  nxusLogWriteError(__VA_ARGS__)
#define NXUS_RESULT(tag, rc) nxusLogWrite("%s: rc=0x%08X", (tag), (unsigned)(rc))
