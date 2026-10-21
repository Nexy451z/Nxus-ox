#include "nxus_dmntcht.h"
#include "nxus_log.h"

#include <string.h>

static Service g_DmntSrv;
static bool    g_DmntActive = false;
/* The automatic ForceOpen retry in Read/Write/GetMetadata is only valid while
   dmnt is supposed to own the target.  The Nxus debug session turns it off for
   the duration of its attach/detach hand-off. */
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

/* ---- process / session ---- */

Result nxusDmntHasCheatProcess(bool *out) {
    if (!g_DmntActive) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    dmntLock();
    Result rc = serviceDispatchOut(&g_DmntSrv, 65000, *out);
    dmntUnlock();
    return rc;
}

Result nxusDmntGetCheatProcessEvent(Handle *out_handle) {
    if (!g_DmntActive) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    dmntLock();
    Result rc = serviceDispatch(&g_DmntSrv, 65001,
        .out_handle_attrs = { SfOutHandleAttr_HipcCopy },
        .out_handles = out_handle);
    dmntUnlock();
    return rc;
}

Result nxusDmntGetMetadata(NxusProcessMetadata *out) {
    if (!g_DmntActive) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    dmntLock();
    Result rc = serviceDispatchOut(&g_DmntSrv, 65002, *out);
    dmntUnlock();

    /* Right after a debug detach (or when the cheat process was torn down by
       sleep/attach churn) dmnt answers with a "process not open" result even
       though the target is alive.  Reopening once and retrying keeps the
       caller from surfacing 0x8003C806 (BAD_STATE) to the PC. */
    if (R_FAILED(rc) && g_AutoReopen) {
        Result open_rc = nxusDmntForceOpen();
        NXUS_LOG("dmnt: GetMetadata failed rc=0x%08X; ForceOpen rc=0x%08X - retrying once",
                 (unsigned)rc, (unsigned)open_rc);
        dmntLock();
        rc = serviceDispatchOut(&g_DmntSrv, 65002, *out);
        dmntUnlock();
    }
    return rc;
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

Result nxusDmntPause(void) {
    if (!g_DmntActive) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    dmntLock();
    Result rc = serviceDispatch(&g_DmntSrv, 65004);
    dmntUnlock();
    return rc;
}

Result nxusDmntResume(void) {
    if (!g_DmntActive) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    dmntLock();
    Result rc = serviceDispatch(&g_DmntSrv, 65005);
    dmntUnlock();
    return rc;
}

/* ---- memory ---- */

Result nxusDmntGetMappingCount(u64 *out_count) {
    if (!g_DmntActive) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    dmntLock();
    Result rc = serviceDispatchOut(&g_DmntSrv, 65100, *out_count);
    dmntUnlock();
    return rc;
}

Result nxusDmntGetMappings(NxusMemoryInfo *buffer, size_t max_count, size_t offset, size_t *out_count) {
    if (!g_DmntActive) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);

    u64 count = 0;
    u64 in_offset = (u64)offset;
    dmntLock();
    Result rc = serviceDispatchInOut(&g_DmntSrv, 65101, in_offset, count,
        .buffer_attrs = { SfBufferAttr_Out | SfBufferAttr_HipcMapAlias },
        .buffers = { { buffer, max_count * sizeof(NxusMemoryInfo) } });
    dmntUnlock();

    if (R_SUCCEEDED(rc) && out_count != NULL) *out_count = (size_t)count;
    return rc;
}

Result nxusDmntQuery(u64 address, NxusMemoryInfo *out) {
    if (!g_DmntActive) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    dmntLock();
    Result rc = serviceDispatchInOut(&g_DmntSrv, 65104, address, *out);
    dmntUnlock();
    return rc;
}

typedef struct NXUS_PACKED {
    u64 address;
    u64 size;
} NxusDmntBufferArgs;

Result nxusDmntRead(u64 address, void *buffer, size_t size) {
    if (!g_DmntActive) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);

    NxusDmntBufferArgs args = { address, (u64)size };
    dmntLock();
    Result rc = serviceDispatchIn(&g_DmntSrv, 65102, args,
        .buffer_attrs = { SfBufferAttr_Out | SfBufferAttr_HipcMapAlias },
        .buffers = { { buffer, size } });
    dmntUnlock();

    /* A read issued in the window between a debug detach and dmnt's cheat
       process coming back fails with "not open" (e.g. 0x0032C80D).  Reopen the
       cheat process once and retry before reporting an error to the caller. */
    if (R_FAILED(rc) && g_AutoReopen) {
        Result open_rc = nxusDmntForceOpen();
        NXUS_LOG("dmnt: Read(%08llX,%u) failed rc=0x%08X; ForceOpen rc=0x%08X - retrying once",
                 (unsigned long long)address, (unsigned)size, (unsigned)rc, (unsigned)open_rc);
        dmntLock();
        rc = serviceDispatchIn(&g_DmntSrv, 65102, args,
            .buffer_attrs = { SfBufferAttr_Out | SfBufferAttr_HipcMapAlias },
            .buffers = { { buffer, size } });
        dmntUnlock();
    }
    return rc;
}

Result nxusDmntWrite(u64 address, const void *buffer, size_t size) {
    if (!g_DmntActive) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);

    NxusDmntBufferArgs args = { address, (u64)size };
    dmntLock();
    Result rc = serviceDispatchIn(&g_DmntSrv, 65103, args,
        .buffer_attrs = { SfBufferAttr_In | SfBufferAttr_HipcMapAlias },
        .buffers = { { buffer, size } });
    dmntUnlock();

    if (R_FAILED(rc) && g_AutoReopen) {
        Result open_rc = nxusDmntForceOpen();
        NXUS_LOG("dmnt: Write(%08llX,%u) failed rc=0x%08X; ForceOpen rc=0x%08X - retrying once",
                 (unsigned long long)address, (unsigned)size, (unsigned)rc, (unsigned)open_rc);
        dmntLock();
        rc = serviceDispatchIn(&g_DmntSrv, 65103, args,
            .buffer_attrs = { SfBufferAttr_In | SfBufferAttr_HipcMapAlias },
            .buffers = { { buffer, size } });
        dmntUnlock();
    }
    return rc;
}

/* ---- frozen addresses (server-side freeze: no PC polling needed) ---- */

Result nxusDmntGetFrozenCount(u64 *out_count) {
    if (!g_DmntActive) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    dmntLock();
    Result rc = serviceDispatchOut(&g_DmntSrv, 65300, *out_count);
    dmntUnlock();
    return rc;
}

Result nxusDmntGetFrozenEntries(NxusFrozenAddressEntry *buffer, size_t max_count, size_t offset, size_t *out_count) {
    if (!g_DmntActive) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);

    u64 count = 0;
    u64 in_offset = (u64)offset;
    dmntLock();
    Result rc = serviceDispatchInOut(&g_DmntSrv, 65301, in_offset, count,
        .buffer_attrs = { SfBufferAttr_Out | SfBufferAttr_HipcMapAlias },
        .buffers = { { buffer, max_count * sizeof(NxusFrozenAddressEntry) } });
    dmntUnlock();

    if (R_SUCCEEDED(rc) && out_count != NULL) *out_count = (size_t)count;
    return rc;
}

Result nxusDmntEnableFrozen(u64 address, u64 width, u64 *out_value) {
    if (!g_DmntActive) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);

    NxusDmntBufferArgs args = { address, width };
    dmntLock();
    Result rc;
    if (out_value != NULL) {
        rc = serviceDispatchInOut(&g_DmntSrv, 65303, args, *out_value);
    } else {
        u64 ignored = 0;
        rc = serviceDispatchInOut(&g_DmntSrv, 65303, args, ignored);
    }
    dmntUnlock();
    return rc;
}

Result nxusDmntDisableFrozen(u64 address) {
    if (!g_DmntActive) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    dmntLock();
    Result rc = serviceDispatchIn(&g_DmntSrv, 65304, address);
    dmntUnlock();
    return rc;
}
