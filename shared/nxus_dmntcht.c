#include "nxus_dmntcht.h"
#include "nxus_log.h"

#include <stdatomic.h>
#include <string.h>

/*
 * Optional hand-off hook into the Nxus debug session (switch/source/nxus_debug.c).
 *
 * dmntRunCommand() below must not ForceOpen() while nxusDebugAttach()/Detach() is
 * handing the process over - even when the decision to reopen was made a moment
 * earlier and nxusDmntSetAutoReopen(false) raced it.  The debug session publishes
 * that state through nxusDebugIsHandoff(); it is not part of this translation unit,
 * and this file is also linked into targets that do not contain the debug session
 * (the probe sysmodule).  The reference is therefore weak: when nxus_debug.c is
 * linked in, its strong definition wins; otherwise the linker resolves the
 * undefined weak symbol to NULL and the guard is skipped.  Neither case produces
 * an undefined symbol / link error.
 */
__attribute__((weak)) bool nxusDmntHandoffBlocked(void);

static Service g_DmntSrv;
static bool    g_DmntActive = false;
/* The automatic ForceOpen retry below is only valid while dmnt is supposed to own
   the target.  The Nxus debug session turns it off for the duration of its
   attach/detach hand-off. */
static volatile bool g_AutoReopen = true;
/* True while one thread is inside the automatic ForceOpen.  Static storage is
   zero-initialised (false), so it is valid before the first atomic operation; no
   worker exists before nxusDmntInitialize() anyway. */
static atomic_bool g_ForceOpenBusy;

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
/* Upper bound for a mapping count accepted from dmnt (sanity, not protocol). */
#define NXUS_DMNT_MAX_MAPPINGS 8192ull

/* A hex view over an unmapped page can fail hundreds of times per second, and every
   NXUS_LOG line is an SD write.  Log the first few, then only every 256th, so a
   broken range cannot flood the card while the cause stays visible. */
static u32 g_ReadFailLogs;
static u32 g_WriteFailLogs;

static bool dmntShouldLogFailure(u32 *counter) {
    const u32 n = (*counter)++;
    return n < 4u || (n % 256u) == 0u;
}

static bool dmntResultIsCheatNotAttached(Result rc) {
    if (R_SUCCEEDED(rc)) return false;

    const u32 raw = (u32)rc;
    if (raw == NXUS_DMNT_RESULT_CHEAT_NOT_ATTACHED) return true;
    /* The same description under Atmosphère's packing: module 0x164 in bits 9..17,
       description 0x0D in bits 0..8.  A looser "low half == 0xC80D" test also
       matches unrelated modules whose description happens to be 0x0D; a false
       positive there would re-open the cheat process (a takeover) for an error
       that has nothing to do with dmnt, so only the exact forms are accepted. */
    return (raw & 0x1FFu) == 0x0Du && ((raw >> 9) & 0x1FFu) == 0x164u;
}

typedef Result (*NxusDmntOp)(void *ctx);

/* dmnt also reports BAD_STATE (0x8003C806) while it tears an old cheat process
   down, so that one is worth a repair attempt.  Everything else - most notably
   0xD401 InvalidCurrentMemory for an unmapped address - is a normal failure of
   the *command*, not of the session. */
#define NXUS_DMNT_RESULT_BAD_STATE 0x8003C806u

/* Re-opening the cheat process is a takeover: dmnt:cht holds one process at a
   time, and ForceOpen steals it from whatever opened it last (EdiZon-SE-style
   cheat sysmodules, another debugger, or Atmosphère's own cheat manager).  Two
   guards keep Nxus from fighting a well-behaved owner:
     - only repair on the two Results above, never on an address failure,
     - at most one attempt every two seconds, with the suppressed count folded
       into a single log line (the log writes to the SD card, so a per-read line
       was both a flood and an I/O cost). */
#define NXUS_DMNT_REOPEN_COOLDOWN_NS 2000000000ull

static u64 g_LastReopenTick = 0;
static u32 g_ReopenSuppressed = 0;

static bool dmntResultMayNeedRepair(Result rc) {
    if (R_SUCCEEDED(rc)) return false;
    if ((u32)rc == NXUS_DMNT_RESULT_BAD_STATE) return true;
    return dmntResultIsCheatNotAttached(rc);
}

/* Run one dmnt command, then repair the cheat process and repeat it once when the
   process has been dropped.
 *
 *   reopen_on_any_failure - historical knob, now ignored: Read/Write/GetMetadata
 *      used to retry after *any* failure, which meant one read of an unmapped
 *      address triggered a ForceOpen (and an SD log line) - the exact behaviour
 *      that stole the cheat process from other tools mid-scan.
 *
 * The retry never happens with auto-reopen disabled: the Nxus debug session owns
 * the process then, and a ForceOpen would take it back mid-attach.
 *
 * That decision is deliberately re-checked right before the takeover.  The check
 * at the top of this function is a check-then-act pair with the ForceOpen below,
 * and nxusDebugAttach()/Detach() can flip the state in between (it calls
 * nxusDmntSetAutoReopen(false) and raises its own hand-off flag).  Acting on the
 * stale value would ForceOpen() and steal the process mid-attach.  Both the
 * volatile flag and the hand-off hook are read again, after the cooldown test so a
 * blocked attempt does not consume the reopen window. */
static Result dmntRunCommand(NxusDmntOp op, void *ctx, bool reopen_on_any_failure, const char *what) {
    (void)reopen_on_any_failure;

    Result rc = op(ctx);
    if (R_SUCCEEDED(rc) || !g_AutoReopen) return rc;
    if (!dmntResultMayNeedRepair(rc)) return rc;

    const u64 now = armGetSystemTick();
    if (g_LastReopenTick != 0 &&
        armTicksToNs(now - g_LastReopenTick) < NXUS_DMNT_REOPEN_COOLDOWN_NS) {
        g_ReopenSuppressed++;
        return rc;
    }

    /* The second check: the debug session may have disabled auto-reopen (or
       started its hand-off) since the check above.  nxusDmntHandoffBlocked() is a
       weak reference, NULL when the debug session is not linked in (read through a
       pointer so the check never trips a "address always true" diagnostic). */
    bool (*handoff_hook)(void) = nxusDmntHandoffBlocked;
    const bool handoff = (handoff_hook != NULL) && handoff_hook();
    if (!g_AutoReopen || handoff) return rc;

    /* Only one ForceOpen at a time: the compare-exchange makes the check-then-act
       above atomic against a second command thread that reached this point with
       the same stale view.  Without it both would reopen - the second one closing
       (or replacing) the process the first just took. */
    bool expected = false;
    if (!atomic_compare_exchange_strong_explicit(&g_ForceOpenBusy, &expected, true,
                                                 memory_order_acq_rel, memory_order_acquire)) {
        return rc;
    }

    g_LastReopenTick = now;
    const u32 suppressed = g_ReopenSuppressed;
    g_ReopenSuppressed = 0;

    Result open_rc = nxusDmntForceOpen();
    atomic_store_explicit(&g_ForceOpenBusy, false, memory_order_release);

    NXUS_LOG("dmnt: %s failed rc=0x%08X; ForceOpen rc=0x%08X (%u deferred) - retrying once",
             what, (unsigned)rc, (unsigned)open_rc, (unsigned)suppressed);
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
    Result rc = dmntRunCommand(opGetMappingCount, out_count, false, "GetMappingCount");
    /* Sanity cap: the mapping count is used to size PC-side loops, so a garbage
       value would keep a client paging forever. */
    if (R_SUCCEEDED(rc) && *out_count > NXUS_DMNT_MAX_MAPPINGS) *out_count = NXUS_DMNT_MAX_MAPPINGS;
    return rc;
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

    /* dmnt answers with the number of entries it wrote; never trust it further
       than the buffer we actually handed over (a larger value would make the
       caller walk past its own allocation). */
    if (R_SUCCEEDED(rc) && out_count != NULL) {
        *out_count = (count > (u64)max_count) ? max_count : (size_t)count;
    }
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
        if (dmntShouldLogFailure(&g_ReadFailLogs)) {
            NXUS_LOG("dmnt: Read(%08llX,%u) rc=0x%08X (repeats suppressed)",
                     (unsigned long long)address, (unsigned)size, (unsigned)rc);
        }
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
        if (dmntShouldLogFailure(&g_WriteFailLogs)) {
            NXUS_LOG("dmnt: Write(%08llX,%u) rc=0x%08X (repeats suppressed)",
                     (unsigned long long)address, (unsigned)size, (unsigned)rc);
        }
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

    if (R_SUCCEEDED(rc) && out_count != NULL) {
        *out_count = (count > (u64)max_count) ? max_count : (size_t)count;
    }
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
