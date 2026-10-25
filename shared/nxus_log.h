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
/* Flush and close the SD stream (it stays open for the whole run).
 *
 * Terminal for this logging lifetime: after this call every nxusLogWriteXXX()
 * (including a line that arrives through the failed-open backoff) is dropped -
 * no ring entry and, above all, no fopen() of the log after the exit.  Only a
 * later nxusLogInit() reopens logging. */
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

/* Bytes of history the ring keeps.  Exposed because the LOG command pages through
   exactly this much: a client that reads it all needs ceil(capacity / length) polls. */
#define NXUS_LOG_RING_CAPACITY 16384u
/* Worst-case length of the generated "... (truncated N bytes)\n" line, so a caller
   can size its buffer for `length` bytes of log PLUS this much. */
#define NXUS_LOG_NOTE_MAX 48u

/* Copy the tail of the ring buffer into out (NUL terminated). Returns bytes written. */
size_t nxusLogTail(char *out, size_t capacity);

/* Copy a window of the ring for the LOG command, cut on line boundaries.
 *
 * The window is addressed BACKWARDS from the newest byte, so one number reaches
 * the whole ring no matter how full it is:
 *
 *   offset  bytes to skip from the END of the ring (0 = newest page)
 *   length  bytes wanted for this poll (0 = the whole remaining window)
 *
 * Only whole lines are returned: a leading partial line (its beginning lies
 * before `offset`) is dropped, and the window ends at the last newline so the
 * reply never stops mid-line.  `capacity` must be at least
 * `length + NXUS_LOG_NOTE_MAX + 1` to get the full window.
 *
 * When anything had to be dropped the reply STARTS with one generated line
 *
 *     ... (truncated N bytes)
 *
 * where N counts the bytes of the requested window the reply does not carry (the
 * partial lines at either end plus anything the caller's buffer could not hold).
 * That note is NOT ring content, which is the paging rule for a client: advance
 * `offset` by (reply length - the note line) to fetch the next older page; the
 * note always ends at the first '\n'.
 *
 * Returns the bytes written (NUL terminated), 0 when the ring is empty, `offset`
 * points past it, or the window holds no complete line.
 */
size_t nxusLogWindow(char *out, size_t capacity, u32 offset, u32 length);

/* Flush the SD file (no-op when SD logging is disabled). */
void nxusLogFlush(void);

/* Every line already carries the "[  12345.678] " uptime prefix; the level only
   decides whether the line is produced at all. */
#define NXUS_LOG(...)        nxusLogWrite(__VA_ARGS__)
#define NXUS_LOG_DEBUG(...)  nxusLogWriteDebug(__VA_ARGS__)
#define NXUS_LOG_ERROR(...)  nxusLogWriteError(__VA_ARGS__)
#define NXUS_RESULT(tag, rc) nxusLogWrite("%s: rc=0x%08X", (tag), (unsigned)(rc))
