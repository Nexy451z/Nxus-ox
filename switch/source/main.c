/*
 * Nxus - Nintendo Switch headless analysis / remote memory editor
 * Sysmodule entry point.
 *
 * Boots the TCP server, the dmnt:cht client, the scan session and the command
 * dispatcher.  All protocol work happens on the connection thread; the main
 * loop only drives the watchdog.
 */
#include <switch.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nxus_debug.h"
#include "nxus_dmntcht.h"
#include "nxus_hid.h"
#include "nxus_log.h"
#include "nxus_net.h"
#include "nxus_protocol.h"
#include "nxus_server.h"
#include "nxus_session.h"
#include "nxus_snapshot_srv.h"

/* Sysmodules must not use applet*. */
u32 __nx_applet_type = AppletType_None;
u32 __nx_fs_num_sessions = 1;

/*
 * Newlib heap inside the sysmodule.
 *   network rx buffer     1MB
 *   scan chunk buffer     1MB   (configurable, halved automatically if refused)
 *   refine window         1MB
 *   hit list (SoA)        <=2.4MB  (150k hits * (8B address + 8B value))
 *   snapshot arrays       0.5MB  (allocated on first use, not at boot)
 *   per-command scratch   <=0.5MB
 *                          ~5.5MB total, so 8MB leaves headroom for code, thread
 * stacks and kernel bookkeeping (Atmosphère gives custom sysmodules ~14MB).
 */
#define INNER_HEAP_SIZE (8 * 1024 * 1024)

#ifdef __cplusplus
extern "C" {
#endif

void __libnx_initheap(void) {
    static u8 inner_heap[INNER_HEAP_SIZE];
    extern void *fake_heap_start;
    extern void *fake_heap_end;

    fake_heap_start = inner_heap;
    fake_heap_end   = inner_heap + sizeof(inner_heap);
}

void __appInit(void) {
    Result rc;

    rc = smInitialize();
    if (R_FAILED(rc)) diagAbortWithResult(MAKERESULT(Module_Libnx, LibnxError_InitFail_SM));

    if (R_SUCCEEDED(setsysInitialize())) {
        SetSysFirmwareVersion fw;
        if (R_SUCCEEDED(setsysGetFirmwareVersion(&fw)))
            hosversionSet(MAKEHOSVERSION(fw.major, fw.minor, fw.micro));
        setsysExit();
    }

    rc = fsInitialize();
    if (R_FAILED(rc)) diagAbortWithResult(MAKERESULT(Module_Libnx, LibnxError_InitFail_FS));
    fsdevMountSdmc();

    rc = nxusDmntInitialize();
    (void)rc;

    /* sm is NOT closed here.  A sysmodule that keeps running needs the sm session
       for every service it opens later: nxusNetInit() calls socketInitializeDefault()
       (bsd:u) and nxusHidStart() calls hidInitialize(), both of which go through
       smGetService().  Calling smExit() drops the last reference and makes every one
       of those calls fail, which on hardware means "no TCP server at all". */
}

void __appExit(void) {
    nxusNetExit();
    nxusHidExit();
    nxusDebugExit();
    nxusSessionExit();
    nxusDmntExit();
    fsdevUnmountAll();
    fsExit();
}

#ifdef __cplusplus
}
#endif

static void logFirmware(void) {
    u32 v = hosversionGet();
    NXUS_LOG("firmware %u.%u.%u", (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF);
}

static void logMetadata(void) {
    NxusProcessMetadata md;
    memset(&md, 0, sizeof(md));
    if (R_FAILED(nxusDmntGetMetadata(&md))) {
        NXUS_LOG("no cheat process attached yet (start a game, then connect)");
        return;
    }
    NXUS_LOG("target: pid=%llu title=%016llX main=%08llX+%08llX heap=%08llX+%08llX",
             (unsigned long long)md.process_id, (unsigned long long)md.program_id,
             (unsigned long long)md.main_nso_base, (unsigned long long)md.main_nso_size,
             (unsigned long long)md.heap_base, (unsigned long long)md.heap_size);
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;

    nxusLogInit(1);
    NXUS_LOG("==============================================");
    NXUS_LOG("Nxus sysmodule (protocol v%u)", (unsigned)NXUS_PROTO_VERSION);
    logFirmware();
    NXUS_LOG("==============================================");

    Result rc = nxusDmntInitialize();
    NXUS_RESULT("dmnt:cht initialize", rc);
    if (R_SUCCEEDED(rc)) {
        bool has_process = false;
        if (R_SUCCEEDED(nxusDmntHasCheatProcess(&has_process)) && !has_process) {
            rc = nxusDmntForceOpen();
            NXUS_RESULT("ForceOpenCheatProcess", rc);
        }
        logMetadata();
    }

    nxusSessionInit(NXUS_SESSION_DEFAULT_CHUNK, NXUS_SESSION_DEFAULT_MAXHITS);
    nxusDebugInit();
    /* Serve a failed snapshot init instead of discovering it on first use: the
       changed-block list is the only part allocated at boot now. */
    rc = nxusSnapshotServiceInit();
    if (R_FAILED(rc)) {
        NXUS_LOG("snapshot service init failed (rc=0x%08X) - snapshot commands will report OOM",
                 (unsigned)rc);
    }
    nxusServerInit();

    rc = nxusNetInit(NXUS_DEFAULT_PORT, nxusServerHandle, NULL);
    NXUS_RESULT("nxusNetInit", rc);
    if (R_FAILED(rc)) {
        NXUS_LOG("TCP server failed to start - sysmodule is idle");
        while (true) svcSleepThread(1000000000ull);
    }

    NXUS_LOG("ready - connect with the PC client on port %u", (unsigned)NXUS_DEFAULT_PORT);

    while (true) {
        nxusServerTick();
        svcSleepThread(100000000ull);   /* 100ms watchdog tick */
    }

    return 0;
}
