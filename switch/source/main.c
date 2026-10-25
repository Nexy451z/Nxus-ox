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
#include <sys/stat.h>

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
 *   hit list (SoA)        <=3.0MB  (dynamic cap from NXUS_SESSION_HIT_BUDGET_BYTES:
 *                                  8B address + value_size per hit, so u8 keeps
 *                                  ~341k hits, u64 ~192k)
 *   baseline block map    <=0.6MB  (Unknown scan only: one entry per 16KB+ block,
 *                                  plus the two block read buffers <=1MB)
 *   snapshot arrays       0.5MB  (allocated on first use, not at boot)
 *   per-command scratch   <=0.5MB
 *                          ~7MB worst case, so 8MB still leaves headroom for code,
 * thread stacks and kernel bookkeeping (Atmosphère gives custom sysmodules ~14MB).
 * An allocation that does not fit degrades gracefully: the baseline falls back to
 * the classic hit-list first pass / stops materialising, it never aborts the scan.
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
    /* The Unknown scan streams its baseline dump to sdmc:/nxus/scan_base.bin, and
       the log file lives in the same directory.  EEXIST is expected; any other
       failure is not fatal because the session falls back to a RAM buffer. */
    (void)mkdir(NXUS_SESSION_BASELINE_DIR, 0777);

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
    nxusLogExit();
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

    /* A boot2 sysmodule usually starts before Wi-Fi is associated, so a single
       failure must not park the module for the whole boot.  nxusNetInit() cleans
       up after itself on failure (socketExit), so retrying is safe. */
    for (u32 attempt = 1; ; attempt++) {
        rc = nxusNetInit(NXUS_DEFAULT_PORT, nxusServerHandle, NULL);
        if (R_SUCCEEDED(rc)) break;
        if (attempt == 1 || (attempt % 20u) == 0) {
            NXUS_LOG("TCP server failed to start rc=0x%08X (attempt %u) - retrying in 3 s",
                     (unsigned)rc, (unsigned)attempt);
        }
        svcSleepThread(3000000000ull);
    }
    NXUS_RESULT("nxusNetInit", rc);

    NXUS_LOG("ready - connect with the PC client on port %u", (unsigned)NXUS_DEFAULT_PORT);

    /* Sleep/wake detection.  armGetSystemTick() keeps counting while the console
       is suspended, so one "100 ms" sleep that took many seconds can mean the
       Switch was asleep.  It can also mean this thread was merely starved while a
       snapshot/pointer scan ran, so a gap alone is NO LONGER enough:
         - 15 s instead of 3 s (a heavy handler can block for several seconds),
         - no reset while a packet was received/sent within the same 15 s window,
         - no reset while a scan is running or a debug session holds the process.
       Only a long gap with no traffic and no active work is a real sleep; then
       every socket is stale (the PC client has timed out too), so drop the old
       connection and rebuild the listener so the PC reconnects to a live :7332. */
    u64 last_tick = armGetSystemTick();
    while (true) {
        nxusServerTick();
        svcSleepThread(100000000ull);   /* 100ms watchdog tick */

        const u64 now_tick = armGetSystemTick();
        const u64 gap_ns = armTicksToNs(now_tick - last_tick);
        if (gap_ns > 15000000000ull) {
            const u64 activity = nxusNetLastActivityTick();
            const bool recent_net =
                (activity != 0) &&
                ((activity >= now_tick) ||
                 (armTicksToNs(now_tick - activity) <= 15000000000ull));
            const bool busy = nxusSessionIsRunning() || nxusDebugIsAttached();
            if (recent_net || busy) {
                NXUS_LOG("long tick (%llu ms) with %s - keeping the network",
                         (unsigned long long)(gap_ns / 1000000ull),
                         recent_net ? "recent network traffic" : "a scan/debug session");
            } else {
                NXUS_LOG("sleep/wake detected (%llu ms in one 100 ms tick) - resetting network",
                         (unsigned long long)(gap_ns / 1000000ull));
                nxusNetRequestReset("sleep-wake");
            }
        }
        last_tick = now_tick;
    }

    return 0;
}
