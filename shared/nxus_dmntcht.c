#include "nxus_dmntcht.h"
#include "nxus_log.h"

#include <string.h>

static Service g_DmntSrv;
static bool    g_DmntActive = false;
/* The automatic ForceOpen retry below is only valid while dmnt is supposed to own
   the target.  The Nxus debug session turns it off for the duration of its
   attach/detach hand-off. */
static volatile bool g_AutoReopen = true;

void nxusDmntSetAutoReopen(bool enabled) {
    g_AutoReopen = enabled;
}

/*
 * Every dmnt:cht dispatch goes through this lock.
 *
 * The scan worker thread reads the target through the same service session that
 * the connection thread uses for status/read/write/pause, and the HID hotkey
 * callback can pause from a third thread.  libnx's serviceDispatch* share the
 * per-Service in/out buffers, so concurrent use is undefined behaviour (corrupt
 * replies, bogus hits, or a stuck sysmodule).  Serialising is cheap: the cost is
 * one uncontended mutex per IPC.
 */
static Mutex g_DmntLock;
static bool  g_DmntLockReady = false;

/* The mutex is created in nxusDmntInitialize(), which the main thread calls
   before any worker exists; every other entry point returns early while the
   service is inactive, so no lazy init is needed here. */
static void dmntLock(void) {
    if (g_DmntLockReady) mutexLock(&g_DmntLock);
}

static void dmntUnlock(void) {
    if (g_DmntLockReady) mutexUnlock(&g_DmntLock);
}

Result nxusDmntInitialize(void) {
    if (!g_DmntLockReady) {
        mutexInit(&g_DmntLock);
        g_DmntLockReady = true;
    }
    if (g_DmntActive) return 0;
    Result rc = smGetService(&g_DmntSrv, "dmnt:cht");
    if (R_SUCCEEDED(rc)) {
        g_DmntActive = true;
    }
    return rc;
}

void nxusDmntExit(void) {
    dmntLock();
    if (g_DmntActive) {
        serviceClose(&g_DmntSrv);
        g_DmntActive = false;
    }
    dmntUnlock();
}

bool nxusDmntIsActive(void) {
    return g_DmntActive;
}

/* ---- automatic cheat-process recovery ---------------------------------- */

/* dmnt:cht answers 0x0032C80D (ResultCheatNotAttached) once it no longer holds a
   cheat process: the title restarted, another debugger took the process over, or
   one earlier IPC failure made dmnt drop the session.  Without a repair path every
   later command keeps returning that Result - which is exactly how a Pause could
   leave the console permanently unable to Read/GetMappings (snapshot capture then
   failed with 0x0032C80D).  ForceOpen once and repeat the failed command once. */
#define NXUS_DMNT_RESULT_CHEAT_NOT_ATTACHED 0x0032C80Du

static bool dmntResultIsCheatNotAttached(Result rc) {
    if (R_SUCCEEDED(rc)) return false;

    const u32 raw = (u32)rc;
    if (raw == NXUS_DMNT_RESULT_CHEAT_NOT_ATTACHED) return true;
    /* The same description under another packing: Atmosphère puts the dmnt module
       (0x164) in bits 9..17 and the description (0x0D) in bits 0..8, while a
       few paths print a module-qualified variant.  Both spellings must trigger
       the repair, so the low half is accepted as well. */
    if ((raw & 0xFFFFu) == 0xC80Du) return true;
    return (raw & 0x1FFu) == 0x0Du && ((raw >> 9) & 0x1FFu) == 0x164u;
}

typedef Result (*NxusDmntOp)(void *ctx);

/* Run one dmnt command, then repair the cheat process and repeat it once when the
   process has been dropped.
 *
 *   reopen_on_any_failure - the historical behaviour of Read/Write/GetMetadata:
 *      those also retried after BAD_STATE (0x8003C806), which dmnt reports while
 *      it tears an old cheat process down.  Every other command only retries on
 *      ResultCheatNotAttached, so an ordinary failure (invalid address, ...) never
 *      steals the process from dmnt.
 *
 * The retry never happens with auto-reopen disabled: the Nxus debug session owns
 * the process then, and a ForceOpen would take it back mid-attach. */
static Result dmntRunCommand(NxusDmntOp op, void *ctx, bool reopen_on_any_failure, const char *what) {
    Result rc = op(ctx);
    if (R_SUCCEEDED(rc) || !g_AutoReopen) return rc;
    if (!reopen_on_any_failure && !dmntResultIsCheatNotAttached(rc)) return rc;

    Result open_rc = nxusDmntForceOpen();
    NXUS_LOG("dmnt: %s failed rc=0x%08X; ForceOpen rc=0x%08X - retrying once",
             what, (unsigned)rc, (unsigned)open_rc);
    if (R_FAILED(open_rc)) return rc;
    return op(ctx);
}

/* ---- process / session ---- */

static Result opHasCheatProcess(void *ctx) {
    bool *out = (bool *)ctx;
    dmntLock();
    Result rc = serviceDispatchOut(&g_DmntSrv, 65000, *out);
    dmntUnlock();
    return rc;
}

Result nxusDmntHasCheatProcess(bool *out) {
    if (!g_DmntActive) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    if (out == NULL) return MAKERESULT(Module_Libnx, LibnxError_BadInput);
    return dmntRunCommand(opHasCheatProcess, out, false, "HasCheatProcess");
}

/* Not retried: a failed handle transfer is not a "cheat process dropped" symptom,
   and repeating it would only produce a second (leaked) copy handle. */
Result nxusDmntGetCheatProcessEvent(Handle *out_handle) {
    if (!g_DmntActive) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    dmntLock();
    Result rc = serviceDispatch(&g_DmntSrv, 65001,
        .out_handle_attrs = { SfOutHandleAttr_HipcCopy },
        .out_handles = out_handle);
    dmntUnlock();
    return rc;
}

static Result opGetMetadata(void *ctx) {
    NxusProcessMetadata *out = (NxusProcessMetadata *)ctx;
    dmntLock();
    Result rc = serviceDispatchOut(&g_DmntSrv, 65002, *out);
    dmntUnlock();
    return rc;
}

Result nxusDmntGetMetadata(NxusProcessMetadata *out) {
    if (!g_DmntActive) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    if (out == NULL) return MAKERESULT(Module_Libnx, LibnxError_BadInput);
    /* Right after a debug detach (or when the cheat process was torn down by
       sleep/attach churn) dmnt answers with a "process not open" result even
       though the target is alive.  Reopening once and retrying keeps the caller
       from surfacing 0x8003C806 (BAD_STATE) / 0x0032C80D to the PC. */
    return dmntRunCommand(opGetMetadata, out, true, "GetMetadata");
}

Result nxusDmntForceOpen(void) {
    if (!g_DmntActive) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    dmntLock();
    Result rc = serviceDispatch(&g_DmntSrv, 65003);
    dmntUnlock();
    return rc;
}

Result nxusDmntForceClose(void) {
    if (!g_DmntActive) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    dmntLock();
    Result rc = serviceDispatch(&g_DmntSrv, 65006);
    dmntUnlock();
    return rc;
}

/* Pause/Resume are real process stops, implemented inside dmnt itself.
 *
 * The command ids are fixed by Atmosphère's ICheatInterface
 * (stratosphere/dmnt/source/cheat/dmnt_cheat_service.hpp; libstratosphere's
 * dmntcht.os.horizon.c and the EdiZon-SE / ldn_mitm copies of that client
 * dispatch the same numbers):
 *
 *   65004 PauseCheatProcess  -> svc::BreakDebugProcess(dmnt's cheat process handle)
 *   65005 ResumeCheatProcess -> svc::ContinueDebugProcess(same handle)
 *
 * dmnt owns the debug handle of the cheat process, so breaking it suspends every
 * thread of the title while dmnt keeps the handle: reads, mappings and snapshots
 * continue to work through the same session.  Its debug-events thread parks on
 * m_unsafe_break_event for as long as m_broken_unsafe is set, so nothing
 * auto-continues behind our back.
 *
 * There is no 65007/65008: the interface jumps from 65006 ForceCloseCheatProcess
 * straight to 65100 GetCheatProcessMappingCount, so dispatching those ids only
 * yields an unknown-command Result and freezes nothing.  Do not "fix" these two
 * ids to anything else without re-reading the header above. */
static Result opPause(void *ctx) {
    (void)ctx;
    dmntLock();
    Result rc = serviceDispatch(&g_DmntSrv, 65004);
    dmntUnlock();
    return rc;
}

static Result opResume(void *ctx) {
    (void)ctx;
    dmntLock();
    Result rc = serviceDispatch(&g_DmntSrv, 65005);
    dmntUnlock();
    return rc;
}

Result nxusDmntPause(void) {
    if (!g_DmntActive) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    /* Normal path for Pause: stops the target without losing the dmnt session, so
       scans / snapshots / frozen addresses keep working while it is held. */
    return dmntRunCommand(opPause, NULL, false, "Pause");
}

Result nxusDmntResume(void) {
    if (!g_DmntActive) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    /* Continues the stop issued by 65004 (also used by the pause watchdog). */
    return dmntRunCommand(opResume, NULL, false, "Resume");
}

/* ---- memory ---- */

static Result opGetMappingCount(void *ctx) {
    u64 *out = (u64 *)ctx;
    dmntLock();
    Result rc = serviceDispatchOut(&g_DmntSrv, 65100, *out);
    dmntUnlock();
    return rc;
}

Result nxusDmntGetMappingCount(u64 *out_count) {
    if (!g_DmntActive) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    if (out_count == NULL) return MAKERESULT(Module_Libnx, LibnxError_BadInput);
    return dmntRunCommand(opGetMappingCount, out_count, false, "GetMappingCount");
}

typedef struct {
    NxusMemoryInfo *buffer;
    size_t          max_count;
    size_t          offset;
    u64            *out_count;   /* dmnt's reply count, written on success */
} DmntMappingsCtx;

static Result opGetMappings(void *ctx) {
    DmntMappingsCtx *c = (DmntMappingsCtx *)ctx;

    u64 count = 0;
    const u64 in_offset = (u64)c->offset;
    dmntLock();
    Result rc = serviceDispatchInOut(&g_DmntSrv, 65101, in_offset, count,
        .buffer_attrs = { SfBufferAttr_Out | SfBufferAttr_HipcMapAlias },
        .buffers = { { c->buffer, c->max_count * sizeof(NxusMemoryInfo) } });
    dmntUnlock();

    if (R_SUCCEEDED(rc)) *c->out_count = count;
    return rc;
}

Result nxusDmntGetMappings(NxusMemoryInfo *buffer, size_t max_count, size_t offset, size_t *out_count) {
    if (!g_DmntActive) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);

    u64 count = 0;
    DmntMappingsCtx ctx = { buffer, max_count, offset, &count };
    Result rc = dmntRunCommand(opGetMappings, &ctx, false, "GetMappings");

    if (R_SUCCEEDED(rc) && out_count != NULL) *out_count = (size_t)count;
    return rc;
}

typedef struct {
    u64            address;
    NxusMemoryInfo *out;
} DmntQueryCtx;

static Result opQuery(void *ctx) {
    DmntQueryCtx *c = (DmntQueryCtx *)ctx;
    dmntLock();
    Result rc = serviceDispatchInOut(&g_DmntSrv, 65104, c->address, *c->out);
    dmntUnlock();
    return rc;
}

Result nxusDmntQuery(u64 address, NxusMemoryInfo *out) {
    if (!g_DmntActive) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    if (out == NULL) return MAKERESULT(Module_Libnx, LibnxError_BadInput);
    DmntQueryCtx ctx = { address, out };
    return dmntRunCommand(opQuery, &ctx, false, "Query");
}

typedef struct NXUS_PACKED {
    u64 address;
    u64 size;
} NxusDmntBufferArgs;

typedef struct {
    u64   address;
    u64   size;
    void *buffer;
} DmntReadCtx;

typedef struct {
    u64         address;
    u64         size;
    const void *buffer;
} DmntWriteCtx;

static Result opRead(void *ctx) {
    DmntReadCtx *c = (DmntReadCtx *)ctx;
    const NxusDmntBufferArgs args = { c->address, c->size };
    dmntLock();
    Result rc = serviceDispatchIn(&g_DmntSrv, 65102, args,
        .buffer_attrs = { SfBufferAttr_Out | SfBufferAttr_HipcMapAlias },
        .buffers = { { c->buffer, (size_t)c->size } });
    dmntUnlock();
    return rc;
}

Result nxusDmntRead(u64 address, void *buffer, size_t size) {
    if (!g_DmntActive) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);

    DmntReadCtx ctx = { address, (u64)size, buffer };
    /* A read issued in the window between a debug detach and dmnt's cheat
       process coming back fails with "not open" (e.g. 0x0032C80D).  Reopen the
       cheat process once and retry before reporting an error to the caller. */
    Result rc = dmntRunCommand(opRead, &ctx, true, "Read");
    if (R_FAILED(rc)) {
        NXUS_LOG("dmnt: Read(%08llX,%u) rc=0x%08X",
                 (unsigned long long)address, (unsigned)size, (unsigned)rc);
    }
    return rc;
}

static Result opWrite(void *ctx) {
    DmntWriteCtx *c = (DmntWriteCtx *)ctx;
    const NxusDmntBufferArgs args = { c->address, c->size };
    dmntLock();
    Result rc = serviceDispatchIn(&g_DmntSrv, 65103, args,
        .buffer_attrs = { SfBufferAttr_In | SfBufferAttr_HipcMapAlias },
        .buffers = { { c->buffer, (size_t)c->size } });
    dmntUnlock();
    return rc;
}

Result nxusDmntWrite(u64 address, const void *buffer, size_t size) {
    if (!g_DmntActive) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);

    DmntWriteCtx ctx = { address, (u64)size, buffer };
    Result rc = dmntRunCommand(opWrite, &ctx, true, "Write");
    if (R_FAILED(rc)) {
        NXUS_LOG("dmnt: Write(%08llX,%u) rc=0x%08X",
                 (unsigned long long)address, (unsigned)size, (unsigned)rc);
    }
    return rc;
}

/* ---- frozen addresses (server-side freeze: no PC polling needed) ---- */

static Result opGetFrozenCount(void *ctx) {
    u64 *out = (u64 *)ctx;
    dmntLock();
    Result rc = serviceDispatchOut(&g_DmntSrv, 65300, *out);
    dmntUnlock();
    return rc;
}

Result nxusDmntGetFrozenCount(u64 *out_count) {
    if (!g_DmntActive) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    if (out_count == NULL) return MAKERESULT(Module_Libnx, LibnxError_BadInput);
    return dmntRunCommand(opGetFrozenCount, out_count, false, "GetFrozenCount");
}

typedef struct {
    NxusFrozenAddressEntry *buffer;
    size_t                  max_count;
    size_t                  offset;
    u64                    *out_count;
} DmntFrozenCtx;

static Result opGetFrozenEntries(void *ctx) {
    DmntFrozenCtx *c = (DmntFrozenCtx *)ctx;

    u64 count = 0;
    const u64 in_offset = (u64)c->offset;
    dmntLock();
    Result rc = serviceDispatchInOut(&g_DmntSrv, 65301, in_offset, count,
        .buffer_attrs = { SfBufferAttr_Out | SfBufferAttr_HipcMapAlias },
        .buffers = { { c->buffer, c->max_count * sizeof(NxusFrozenAddressEntry) } });
    dmntUnlock();

    if (R_SUCCEEDED(rc)) *c->out_count = count;
    return rc;
}

Result nxusDmntGetFrozenEntries(NxusFrozenAddressEntry *buffer, size_t max_count, size_t offset, size_t *out_count) {
    if (!g_DmntActive) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);

    u64 count = 0;
    DmntFrozenCtx ctx = { buffer, max_count, offset, &count };
    Result rc = dmntRunCommand(opGetFrozenEntries, &ctx, false, "GetFrozenEntries");

    if (R_SUCCEEDED(rc) && out_count != NULL) *out_count = (size_t)count;
    return rc;
}

typedef struct {
    u64   address;
    u64   width;
    u64  *out_value;   /* may be NULL */
    u64   ignored;
} DmntEnableFrozenCtx;

static Result opEnableFrozen(void *ctx) {
    DmntEnableFrozenCtx *c = (DmntEnableFrozenCtx *)ctx;
    const NxusDmntBufferArgs args = { c->address, c->width };
    u64 *out = (c->out_value != NULL) ? c->out_value : &c->ignored;
    dmntLock();
    Result rc = serviceDispatchInOut(&g_DmntSrv, 65303, args, *out);
    dmntUnlock();
    return rc;
}

Result nxusDmntEnableFrozen(u64 address, u64 width, u64 *out_value) {
    if (!g_DmntActive) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);

    DmntEnableFrozenCtx ctx = { address, width, out_value, 0 };
    return dmntRunCommand(opEnableFrozen, &ctx, false, "EnableFrozen");
}

static Result opDisableFrozen(void *ctx) {
    const u64 *address = (const u64 *)ctx;
    dmntLock();
    Result rc = serviceDispatchIn(&g_DmntSrv, 65304, *address);
    dmntUnlock();
    return rc;
}

Result nxusDmntDisableFrozen(u64 address) {
    if (!g_DmntActive) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    return dmntRunCommand(opDisableFrozen, &address, false, "DisableFrozen");
}
