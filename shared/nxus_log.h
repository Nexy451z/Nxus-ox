/* Nxus logging: in-memory ring buffer (readable over the protocol) + SD file. */
#pragma once

#include <switch.h>
#include <stddef.h>

void nxusLogInit(int write_to_sd);
/* Flush and close the SD stream (it stays open for the whole run). */
void nxusLogExit(void);
void nxusLogWrite(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void nxusLogEvent(u32 event_id, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

/* Copy the tail of the ring buffer into out (NUL terminated). Returns bytes written. */
size_t nxusLogTail(char *out, size_t capacity);

/* Flush the SD file (no-op when SD logging is disabled). */
void nxusLogFlush(void);

#define NXUS_LOG(...)        nxusLogWrite(__VA_ARGS__)
#define NXUS_RESULT(tag, rc) nxusLogWrite("%s: rc=0x%08X", (tag), (unsigned)(rc))
