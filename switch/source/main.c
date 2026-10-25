/*
 * Nxus - Nintendo Switch headless analysis / remote memory editor
 * Sysmodule entry point.
 *
 * Boots the TCP server, the dmnt:cht client, the scan session and the command
 * dispatcher.  All protocol work happens on the connection thread; the main
 * loop only drives the watchdog.
 */
#include <switch.h>

#include <stdarg.h>
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

/* ---------------------------------------------------------------------------
 * Boot diagnostics.
 *
 * A failure inside __appInit() never reaches main(), so the old "nxusLogInit(1)
 * as the first statement of main()" left the abort completely silent: the fatal
 * report carried only a generic libnx placeholder and the SD card had no line
 * saying which service failed.  The log itself needs the SD card, so the order
 * is fsdevMountSdmc -> nxusLogInit -> every other init step:
 *   - sm / fs / the SD mount itself run before any storage exists, so their only
 *     record is the abort result,
 *   - from the mount onwards every failure is written before aborting: to
 *     boot_fail.txt in the short window before the log opens, to nxus.log after,
 * and every failure is passed to diagAbortWithResult() unchanged so the fatal
 * report names the real service error.
 * ------------------------------------------------------------------------- */
static bool g_SdMounted = false;   /* fsdevMountSdmc() succeeded */
static bool g_LogReady  = false;   /* nxusLogInit() has run */

#define NXUS_BOOT_FAIL_PATH (NXUS_SESSION_BASELINE_DIR "/boot_fail.txt")

/* Write one line: through the log once it exists, otherwise as an append to
   boot_fail.txt.  Nothing is attempted before the SD mount - fopen() on an
   unmounted sdmc:/ would fail, and NXUS_LOG() would take a mutex that
   nxusLogInit() has not initialised yet. */
static void bootNoteWrite(const char *msg) {
    if (g_LogReady) {
        NXUS_LOG("%s", msg);
        /* An abort may follow immediately: do not leave the line in the 4 KiB
           buffered window. */
        nxusLogFlush();
        return;
    }
    if (!g_SdMounted) return;
    (void)mkdir(NXUS_SESSION_BASELINE_DIR, 0777);
    FILE *f = fopen(NXUS_BOOT_FAIL_PATH, "ab");
    if (f == NULL) return;
    fprintf(f, "%s\n", msg);
    fclose(f);
}

static void bootNote(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

static void bootNote(const char *fmt, ...) {
    char msg[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    bootNoteWrite(msg);
}

/* Record the failing step, then abort.  The Result is forwarded unchanged: the
   real error (e.g. 0x00000A3C from fs) is worth more in the fatal report than
   the LibnxError_InitFail_* placeholder the old code substituted. */
static void bootFail(const char *stage, Result rc) {
    bootNote("boot fail: %s rc=0x%08X", stage, (unsigned)rc);
    diagAbortWithResult(rc);
}

void __appInit(void) {
    Result rc;

    /* Steps that must work before the log can exist (no SD access yet). */
    rc = smInitialize();
    if (R_FAILED(rc)) bootFail("smInitialize", rc);

    rc = fsInitialize();
    if (R_FAILED(rc)) bootFail("fsInitialize", rc);

    rc = fsdevMountSdmc();
    if (R_FAILED(rc)) {
        /* No SD card: the log file and the streaming baseline are unavailable, but
           memory scanning, the debugger and TCP all still work from RAM.  Keep the
           module usable instead of aborting the whole sysmodule - the failure is
           still visible in the fatal report if something else fails later. */
        g_SdMounted = false;
    } else {
        g_SdMounted = true;
    }

    /* The Unknown scan streams its baseline dump to sdmc:/nxus/scan_base.bin; the
       log and boot_fail.txt live in the same directory.  EEXIST is expected; any
       other failure is not fatal because the session falls back to a RAM buffer. */
    (void)mkdir(NXUS_SESSION_BASELINE_DIR, 0777);

    /* SD is reachable: the log starts here, before every remaining init step, so
       failures below are written to sdmc:/nxus/nxus.log before the abort. */
    nxusLogInit(1);
    g_LogReady = true;
    NXUS_LOG("boot: sdmc mounted, log started");

    /* Firmware version is informational - a failure only costs the number in the
       log header, so record it and keep booting. */
    rc = setsysInitialize();
    if (R_SUCCEEDED(rc)) {
        SetSysFirmwareVersion fw;
        Result fw_rc = setsysGetFirmwareVersion(&fw);
        if (R_SUCCEEDED(fw_rc))
            hosversionSet(MAKEHOSVERSION(fw.major, fw.minor, fw.micro));
        else
            bootNote("boot warn: setsysGetFirmwareVersion rc=0x%08X", (unsigned)fw_rc);
        setsysExit();
    } else {
        bootNote("boot warn: setsysInitialize rc=0x%08X", (unsigned)rc);
    }

    /* dmnt:cht is not fatal either: scans still work without a debug handle, and
       main() logs this same Result again through NXUS_RESULT(). */
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

    /* The log is normally already open: __appInit() starts it right after the SD
       mount so that boot failures are recorded.  This call stays as the first
       statement of main() as a safety net, but re-initialising an open log would
       wipe the ring buffer and drop those boot lines from the `log` command, so
       it only runs when __appInit() did not get there. */
    if (!g_LogReady) {
        nxusLogInit(1);
        g_LogReady = true;
    }

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

    /* One explicit success marker for the init chain, written before the network
       wait: a boot2 sysmodule can sit in the retry loop below for a long time
       (Wi-Fi not associated yet), and without this line the log looked identical
       to a boot that died halfway.  "ready" is logged separately once the
       listener is actually up. */
    NXUS_LOG("boot ok: init chain complete (dmnt/session/debug/snapshot/server)");

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
