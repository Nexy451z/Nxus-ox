/*
 * Host stand-in for the nxus_session_* surface that switch/source/
 * nxus_snapshot_srv.c calls.  See nxus_session_stub.h for the model and
 * tests/test_snapshot_owner.c for how it is driven.
 *
 * The release build links the real nxus_session.c here; on the host the test
 * replaces it so the identity can be moved between captures.  Nothing below is
 * copied from the shipped implementation: these are deliberately trivial
 * definitions of the same prototypes (checked against nxus_session.h by the
 * compiler), so a signature change in the session breaks this file instead of
 * silently testing a stale interface.
 */
#include "nxus_session_stub.h"

#include "nxus_log.h"
#include "nxus_session.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* ---- fake target state -------------------------------------------------- */

static u64  g_Pid = NXUS_TEST_PID_A;
static u64  g_ProgramId = NXUS_TEST_TITLE_A;
static u32  g_SessionId = 1;
static bool g_Readable = true;
static bool g_PinAvailable = true;
static Result g_PrepareResult = 0;

/* What the service under test did, so the tests can check the plumbing: the
   capture must take exactly one pin and drop it on every path (including the
   failures), and a failed capture must not have read any memory. */
static u32 g_PrepareCalls;
static u32 g_Reads;
static u32 g_OutstandingPins;
static u32 g_NextPinId = 1;

static u8 g_Memory[NXUS_TEST_REGION_SIZE];
static NxusScanRegion g_Region;
static char g_LastLog[1024];

void nxusTestSessionReset(void) {
    g_Pid = NXUS_TEST_PID_A;
    g_ProgramId = NXUS_TEST_TITLE_A;
    g_SessionId = 1;
    g_Readable = true;
    g_PinAvailable = true;
    g_PrepareResult = 0;

    g_PrepareCalls = 0;
    g_Reads = 0;
    g_OutstandingPins = 0;
    g_NextPinId = 1;

    memset(g_Memory, 0, sizeof(g_Memory));
    memset(&g_Region, 0, sizeof(g_Region));
    g_Region.base = NXUS_TEST_REGION_BASE;
    g_Region.size = NXUS_TEST_REGION_SIZE;
    g_Region.perm = NXUS_PERM_R;
    g_Region.mapping_idx = 0;
    g_Region.addr_base = 0;

    g_LastLog[0] = '\0';
}

void nxusTestSessionSetIdentity(u64 pid, u64 program_id, u32 session_id) {
    g_Pid = pid;
    g_ProgramId = program_id;
    g_SessionId = session_id;
}

void nxusTestSessionSetReadable(bool readable) { g_Readable = readable; }
void nxusTestSessionSetPinAvailable(bool available) { g_PinAvailable = available; }
void nxusTestSessionSetPrepareResult(Result rc) { g_PrepareResult = rc; }

u32 nxusTestSessionPrepareCalls(void) { return g_PrepareCalls; }
u32 nxusTestSessionReads(void) { return g_Reads; }
u32 nxusTestSessionOutstandingPins(void) { return g_OutstandingPins; }

u8 *nxusTestSessionMemory(void) { return g_Memory; }
u64 nxusTestSessionRegionBase(void) { return NXUS_TEST_REGION_BASE; }
u32 nxusTestSessionRegionSize(void) { return (u32)NXUS_TEST_REGION_SIZE; }

const char *nxusTestLastLog(void) { return g_LastLog; }
void nxusTestLogClear(void) { g_LastLog[0] = '\0'; }

/* ---- nxus_session_* entry points ---------------------------------------- */

u64 nxusSessionProcessId(void) { return g_Pid; }
u64 nxusSessionProgramId(void) { return g_ProgramId; }
u32 nxusSessionId(void) { return g_SessionId; }

Result nxusSessionPrepareRegions(u32 scope, u64 range_begin, u64 range_end) {
    (void)scope;
    (void)range_begin;
    (void)range_end;
    g_PrepareCalls++;
    return g_PrepareResult;
}

/* One region is always published; "every read fails" is simulated in the read
   callback so the capture (not the region preparation) is what fails. */
bool nxusSessionViewPinCurrent(NxusViewPin *out) {
    if (out == NULL) return false;
    out->id = 0;
    out->generation = 0;
    if (!g_PinAvailable) return false;
    out->id = g_NextPinId++;
    out->generation = 1;
    g_OutstandingPins++;
    return true;
}

void nxusSessionViewUnpin(NxusViewPin *pin) {
    if (pin == NULL) return;
    if (pin->id != 0 && g_OutstandingPins > 0) g_OutstandingPins--;
    pin->id = 0;
    pin->generation = 0;
}

const NxusScanRegion *nxusSessionRegionsPinned(const NxusViewPin *pin, u32 *out_count) {
    if (out_count != NULL) *out_count = 0;
    if (pin == NULL || pin->id == 0 || g_OutstandingPins == 0) return NULL;
    if (out_count != NULL) *out_count = 1;
    return &g_Region;
}

int nxusSessionReadCallback(void *ctx, u64 address, void *buffer, u32 size) {
    (void)ctx;
    g_Reads++;
    if (!g_Readable) return -1;                 /* target memory went away */
    if (buffer == NULL || address < NXUS_TEST_REGION_BASE) return -1;
    const u64 offset = address - NXUS_TEST_REGION_BASE;
    if (offset > NXUS_TEST_REGION_SIZE ||
        size > NXUS_TEST_REGION_SIZE - (u32)offset) return -1;
    memcpy(buffer, g_Memory + offset, size);
    return 0;
}

/* ---- logging ------------------------------------------------------------ */

static void logStore(const char *fmt, va_list ap) {
    vsnprintf(g_LastLog, sizeof(g_LastLog), fmt, ap);
}

void nxusLogWrite(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    logStore(fmt, ap);
    va_end(ap);
}

void nxusLogWriteDebug(const char *fmt, ...) {
    (void)fmt;                                  /* only info/error lines matter here */
}

void nxusLogWriteError(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    logStore(fmt, ap);
    va_end(ap);
}
