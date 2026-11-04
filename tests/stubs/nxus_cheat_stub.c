/*
 * Host stand-in for the session / dmnt / HID / server / net surface that
 * switch/source/nxus_cheat_srv.c calls.  See nxus_cheat_stub.h for the model and
 * tests/test_cheat_srv.c for how it is driven.
 *
 * The release build links the real nxus_session.c, nxus_dmntcht.c, nxus_hid.c,
 * nxus_server.c and nxus_net.c here; on the host the test replaces them so the
 * identity can be moved between ticks and writes can be made to fail.  Nothing
 * below is copied from the shipped implementation: these are deliberately trivial
 * definitions of the same prototypes (checked against the real headers by the
 * compiler), so a signature change breaks this file instead of silently testing a
 * stale interface.
 */
#include "nxus_cheat_stub.h"

#include "nxus_debug.h"
#include "nxus_dmntcht.h"
#include "nxus_hid.h"
#include "nxus_log.h"
#include "nxus_net.h"
#include "nxus_server.h"
#include "nxus_session.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* ---- fake target state -------------------------------------------------- */

static u64  g_Pid = CHEAT_TEST_PID_A;
static u64  g_ProgramId = CHEAT_TEST_TITLE_A;
static u32  g_Incarnation = 1;
static bool g_IdentityBroken = false;
static bool g_Readable = true;
static bool g_Writable = true;
static bool g_RangeAllowed = true;
static bool g_DebugAttached = false;
static bool g_ServerExited = false;
static u64  g_HeldMask = 0;

static u8 g_Memory[CHEAT_TEST_SIZE];

static u32 g_Writes;
static u32 g_WritesOk;
static u32 g_Reads;
static u32 g_PlainChecks;
static u32 g_PatchChecks;
static u32 g_HeldMaskReads;

static u32 g_EventCount;
static u16 g_LastEventType;
static u32 g_LastEventLength;
static NxusCheatFault g_LastFault;

static char g_LastLog[1024];
static char g_LastDebugLog[1024];

static bool cheatMemoryRange(u64 address, u32 size) {
    if (address < CHEAT_TEST_BASE) return false;
    const u64 offset = address - CHEAT_TEST_BASE;
    if (offset > (u64)CHEAT_TEST_SIZE) return false;
    return (u64)size <= (u64)CHEAT_TEST_SIZE - offset;
}

void cheatTestReset(void) {
    g_Pid = CHEAT_TEST_PID_A;
    g_ProgramId = CHEAT_TEST_TITLE_A;
    g_Incarnation = 1;
    g_IdentityBroken = false;
    g_Readable = true;
    g_Writable = true;
    g_RangeAllowed = true;
    g_DebugAttached = false;
    g_ServerExited = false;
    g_HeldMask = 0;

    g_Writes = 0;
    g_WritesOk = 0;
    g_Reads = 0;
    g_PlainChecks = 0;
    g_PatchChecks = 0;
    g_HeldMaskReads = 0;

    g_EventCount = 0;
    g_LastEventType = 0;
    g_LastEventLength = 0;
    memset(&g_LastFault, 0, sizeof(g_LastFault));

    memset(g_Memory, 0, sizeof(g_Memory));
    g_LastLog[0] = '\0';
    g_LastDebugLog[0] = '\0';
}

void cheatTestSetIdentity(u64 pid, u64 program_id) {
    g_Pid = pid;
    g_ProgramId = program_id;
}
void cheatTestSetIncarnation(u32 incarnation) { g_Incarnation = incarnation; }
void cheatTestSetIdentityBroken(bool broken) { g_IdentityBroken = broken; }
void cheatTestSetReadable(bool readable) { g_Readable = readable; }
void cheatTestSetWritable(bool writable) { g_Writable = writable; }
void cheatTestSetRangeAllowed(bool allowed) { g_RangeAllowed = allowed; }
void cheatTestSetDebugAttached(bool attached) { g_DebugAttached = attached; }
void cheatTestSetServerExited(bool exited) { g_ServerExited = exited; }
void cheatTestSetHeldMask(u64 mask) { g_HeldMask = mask; }

u8 *cheatTestMemory(void) { return g_Memory; }

void cheatTestPoke(u64 address, const void *data, u32 size) {
    if (!cheatMemoryRange(address, size)) return;
    memcpy(g_Memory + (address - CHEAT_TEST_BASE), data, size);
}

u32 cheatTestPeekU32(u64 address) {
    u32 value = 0;
    if (!cheatMemoryRange(address, sizeof(value))) return 0;
    memcpy(&value, g_Memory + (address - CHEAT_TEST_BASE), sizeof(value));
    return value;
}

u32 cheatTestWrites(void) { return g_Writes; }
u32 cheatTestWritesOk(void) { return g_WritesOk; }
u32 cheatTestPlainRangeChecks(void) { return g_PlainChecks; }
u32 cheatTestPatchRangeChecks(void) { return g_PatchChecks; }
u32 cheatTestHeldMaskReads(void) { return g_HeldMaskReads; }
u32 cheatTestReads(void) { return g_Reads; }

u32 cheatTestEventCount(void) { return g_EventCount; }
u16 cheatTestLastEventType(void) { return g_LastEventType; }
u32 cheatTestLastEventLength(void) { return g_LastEventLength; }
const NxusCheatFault *cheatTestLastFault(void) { return &g_LastFault; }
void cheatTestClearEvents(void) {
    g_EventCount = 0;
    g_LastEventType = 0;
    g_LastEventLength = 0;
    memset(&g_LastFault, 0, sizeof(g_LastFault));
}

const char *cheatTestLastLog(void) { return g_LastLog; }
void cheatTestLogClear(void) {
    g_LastLog[0] = '\0';
    g_LastDebugLog[0] = '\0';
}

/* ---- nxus_session_* ----------------------------------------------------- */

bool nxusSessionTargetIdentity(NxusTargetIdentity *out) {
    if (g_IdentityBroken) return false;
    if (out != NULL) {
        out->pid = g_Pid;
        out->program_id = g_ProgramId;
        out->main_base = CHEAT_TEST_BASE;
        out->main_size = CHEAT_TEST_SIZE;
        out->generation = 1;
    }
    return true;
}

int nxusSessionReadMemory(u64 address, void *buffer, u32 size) {
    g_Reads++;
    if (!g_Readable) return -1;
    if (buffer == NULL || !cheatMemoryRange(address, size)) return -1;
    memcpy(buffer, g_Memory + (address - CHEAT_TEST_BASE), size);
    return 0;
}

bool nxusSessionCheckRange(u64 address, u64 size, bool require_writable) {
    g_PlainChecks++;
    if (!g_RangeAllowed) return false;
    if (require_writable && !g_Writable) return false;
    return size != 0 && cheatMemoryRange(address, (u32)size);
}

bool nxusSessionCheckCodePatchRange(u64 address, u64 size) {
    g_PatchChecks++;
    if (!g_RangeAllowed) return false;
    /* The real check accepts read + (write OR execute); the stub's fake target is
     * readable, so "allowed" is what the test decides. */
    return size != 0 && cheatMemoryRange(address, (u32)size);
}

/* ---- dmnt / debug / hid / server / net ---------------------------------- */

Result nxusDmntWrite(u64 address, const void *buffer, size_t size) {
    g_Writes++;
    if (!g_Writable || buffer == NULL || size == 0) return (Result)1;
    if (address < CHEAT_TEST_BASE || size > CHEAT_TEST_SIZE ||
        address - CHEAT_TEST_BASE > CHEAT_TEST_SIZE - size) {
        return (Result)1;
    }
    memcpy(g_Memory + (address - CHEAT_TEST_BASE), buffer, size);
    g_WritesOk++;
    return 0;
}

Result nxusDmntRead(u64 address, void *buffer, size_t size) {
    return nxusSessionReadMemory(address, buffer, (u32)size) == 0 ? 0 : (Result)1;
}

u32 nxusDmntTargetIncarnation(void) { return g_Incarnation; }

u64 nxusHidHeldMask(void) {
    g_HeldMaskReads++;
    return g_HeldMask;
}

bool nxusDebugIsAttached(void) { return g_DebugAttached; }

bool nxusServerHasExited(void) { return g_ServerExited; }

Result nxusNetSendEvent(u16 type, const void *payload, u32 length) {
    g_EventCount++;
    g_LastEventType = type;
    g_LastEventLength = length;
    if (payload != NULL && length >= sizeof(NxusCheatFault)) {
        memcpy(&g_LastFault, payload, sizeof(g_LastFault));
    }
    return 0;
}

Result nxusNetSendFd(int fd, u16 type, u16 flags, u32 seq, const void *payload, u32 length) {
    (void)fd; (void)type; (void)flags; (void)seq; (void)payload; (void)length;
    return 0;
}

/* ---- logging ------------------------------------------------------------ */

void nxusLogWrite(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_LastLog, sizeof(g_LastLog), fmt, ap);
    va_end(ap);
}

void nxusLogWriteDebug(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_LastDebugLog, sizeof(g_LastDebugLog), fmt, ap);
    va_end(ap);
}

void nxusLogWriteError(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_LastLog, sizeof(g_LastLog), fmt, ap);
    va_end(ap);
}
