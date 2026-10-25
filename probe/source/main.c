/*
 * Nxus hardware probe.
 *
 * Purpose: on the day the console arrives, answer the questions that cannot be
 * answered on an emulator or on the host, and write the answers to
 * sdmc:/nxus/probe.txt:
 *
 *   1. does this console's Atmosphère let a *custom sysmodule* open a kernel
 *      debug session (svcDebugActiveProcess) ?
 *   2. which hardware-breakpoint ctrl words does the kernel accept
 *      (bits 17/18/19 NPDM debug flags, execute bp, watchpoints, linked ctx-id bp)?
 *   3. are hardware breakpoints per-core on this kernel?
 *   4. what does dmnt:cht report for the running title (base/heap/mappings)?
 *   5. can we read a thread context while stopped?
 *
 * The probe is deliberately conservative: it never terminates the target,
 * it always continues every thread it stopped, clears what it set, and closes
 * the debug handle when done.  The game freezes for well under a second.
 *
 * The report is APPENDED to, never truncated: the point of a probe run is to
 * compare it with the run before it.  Each run starts with a separator line (ISO
 * 8601 UTC, title, firmware), then that run's verdict, then the details, and the
 * file is rotated to "<path>.1" once it passes 512 KiB.
 */
#include <switch.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "nxus_dmntcht.h"
#include "nxus_hid.h"
#include "nxus_protocol.h"
/* nxusPtrScanArchFromAddressSpace(): the console-side rule for "is this an
   AArch32 or AArch64 process?", reused here so the probe reports the same bitness
   the pointer scan will walk with (core/nxus_ptrscan.c, linked into the probe). */
#include "nxus_ptrscan.h"

u32 __nx_applet_type = AppletType_None;
u32 __nx_fs_num_sessions = 1;

#define INNER_HEAP_SIZE (2u * 1024 * 1024)
#define PROBE_LOG_FILE  "sdmc:/nxus/probe.txt"
#define PROBE_CFG_FILE  "sdmc:/nxus/probe_target.txt"
#define MAX_MAPPINGS    512

/* How long the probe waits for a game before it gives up and reports whatever it
   could measure.  This used to be 120 s, which parked the only thread of this
   sysmodule for two minutes on every boot where no game was started yet; see
   waitForTarget() for why a (short) wait is still needed. */
#define TARGET_WAIT_MS  30000u

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
    if (R_FAILED(smInitialize())) diagAbortWithResult(MAKERESULT(Module_Libnx, LibnxError_InitFail_SM));

    /* firmware version, so the probe report is self-describing */
    if (R_SUCCEEDED(setsysInitialize())) {
        SetSysFirmwareVersion fw;
        if (R_SUCCEEDED(setsysGetFirmwareVersion(&fw)))
            hosversionSet(MAKEHOSVERSION(fw.major, fw.minor, fw.micro));
        setsysExit();
    }

    if (R_FAILED(fsInitialize())) diagAbortWithResult(MAKERESULT(Module_Libnx, LibnxError_InitFail_FS));
    fsdevMountSdmc();

    /* dmnt:cht must be opened while the sm session is still alive, and the probe
       also opens hid (probeHid) and the SD card later.  smExit() would drop the
       last reference and make all of those fail, so the session stays open. */
    nxusDmntInitialize();

    /* pm:dmnt reports the foreground application's process id as soon as a game
       runs - unlike dmnt's cheat process, which only appears for auto-attached
       titles.  waitForTarget() needs exactly that signal. */
    pmdmntInitialize();
}

void __appExit(void) {
    fsdevUnmountAll();
    fsExit();
}

#ifdef __cplusplus
}
#endif

static FILE *g_Out = NULL;
static u64   g_Pid = 0;
static u64   g_MainBase = 0, g_MainSize = 0;
static u64   g_HeapBase = 0, g_HeapSize = 0;
static u64   g_ExecTarget = 0;
static u64   g_WatchTarget = 0;

/* Which fallback path the report was opened on (see main()), so the "done" line and
   the fallback note name the file that was actually written. */
static const char *g_ReportPath = NULL;

/* ---- what this run measured, for the verdict block at the top of the report ---
 * The verdict is written before the details, i.e. before the details can be
 * summarised from the report text, so every fact it needs is recorded here by the
 * probe that measured it.  Keeping them apart from the local Result variables also
 * makes "not attempted" (no target) distinguishable from "failed". */
static bool   g_TargetFound;        /* waitForTarget() saw a running title       */
static u64    g_TargetFoundMs;      /* how long that took                        */
static u64    g_TitleId;            /* program id of the foreground title, or 0  */
static bool   g_DmntInitOk;         /* dmnt:cht opened                            */
static Result g_DmntInitRc;
static bool   g_DmntMdTried;        /* GetCheatProcessMetadata was reached        */
static Result g_DmntMdRc;
static bool   g_DbgTried;           /* svcDebugActiveProcess was reached          */
static Result g_DbgRc;
static u32    g_HwbpAccepted;       /* candidate control words the kernel took    */
static u32    g_HwbpRejected;
static u32    g_ExecDelivered;      /* instruction breakpoint exceptions received */
static u32    g_DataDelivered;      /* data breakpoint exceptions received        */
static bool   g_PerCoreTested;      /* probePerCore() ran at all                  */
static bool   g_HidTried;
static Result g_HidRc;
static u64    g_HidButtons;

/* svcSetHardwareBreakPoint only programs the debug registers of the core the
   calling thread is currently on.  Nxus runs on core 3 while the game runs on
   cores 0-2, which is exactly why the product's breakpoints never fired: every
   slot has to be written once per core.  Migrate the caller through cores 0-3 and
   restore its original affinity afterwards, like Atmosphère's
   dmnt2_hardware_breakpoint.cpp. */

/* Declared here because setHwBpAllCores() has to report a failed migration to
   probe.txt, and the reporter itself is defined further down. */
static void out(const char *fmt, ...);

/* Core migrations that failed anywhere in this run.  A failed migration leaves the
   caller on the previous core, so the same registers are written again and the
   cores that matter stay untouched: every core would then have been measured with
   the same value, which makes the "are breakpoints per-core?" verdict below a lie
   unless this stays 0. */
static u32    g_PerCoreFailures;
static Result g_LastCoreMigrateRc;

static Result setHwBpAllCores(u32 slot, u64 ctrl, u64 value) {
    s32 orig_core = 0;
    u64 orig_mask = 0;
    Result mrc = svcGetThreadCoreMask(&orig_core, &orig_mask, CUR_THREAD_HANDLE);
    Result first_err = 0;

    /* Without the mask nothing can be migrated, so all four writes would land on
       one core.  Report that instead of pretending the write was per-core. */
    if (R_FAILED(mrc)) {
        out("  svcGetThreadCoreMask rc=0x%08X - cannot migrate, per-core arming unverified",
            (unsigned)mrc);
        g_PerCoreFailures++;
        g_LastCoreMigrateRc = mrc;
        first_err = mrc;
    }

    for (s32 core = 0; core < 4; core++) {
        if (R_SUCCEEDED(mrc)) {
            Result crc = svcSetThreadCoreMask(CUR_THREAD_HANDLE, core, (1ull << core));
            if (R_FAILED(crc)) {
                /* Do not write on the wrong core: skip it and remember the result,
                   so the caller sees a failure instead of a partially armed set. */
                out("  core %d への移行に失敗 rc=0x%08X (このコアへの書き込みはスキップ)",
                    (int)core, (unsigned)crc);
                g_PerCoreFailures++;
                g_LastCoreMigrateRc = crc;
                if (R_SUCCEEDED(first_err)) first_err = crc;
                continue;
            }
        }
        Result rc = svcSetHardwareBreakPoint(slot, ctrl, value);
        if (R_FAILED(rc) && R_SUCCEEDED(first_err)) first_err = rc;
    }
    if (R_SUCCEEDED(mrc)) {
        Result rrc = svcSetThreadCoreMask(CUR_THREAD_HANDLE, orig_core, orig_mask);
        if (R_FAILED(rrc)) {
            out("  could not restore the original core mask (core %d) rc=0x%08X",
                (int)orig_core, (unsigned)rrc);
        }
    }
    return first_err;
}

/* The control word the product uses for an execution breakpoint linked to the
   context-id breakpoint in slot 5: BT=0b0001 (linked instruction address match),
   LBN=5, BAS=0xF, E=1.  The kernel rejects the unlinked form with 0xE801. */
#define HWBP_EXEC_LINK5  0x001501E1ull
/* LINKED_CONTEXT_IDR_MATCH (BT = 0b0011), value = debug handle.  The product arms
   this unconditionally, because every execution breakpoint links to it. */
#define HWBP_CTX_LINK5   0x003001E1ull

/* ---- report writer: append-only, verdict before details ------------------
 * The report is opened with "ab" (never "wb"): a run that truncated the file made
 * the previous run disappear, which is exactly what a probe report is for.
 *
 * The verdict of a run is only known after the last probe, but it has to be the
 * first thing after the separator, and an append stream cannot be rewound.  So the
 * details are spooled in RAM and copied out after the verdict: the out() call order
 * survives untouched, and the only lines written live are the ones that must be
 * visible while the probe still runs (the run separator, the target wait's progress
 * and the verdict).
 */
#define PROBE_LOG_MAX_BYTES (512u * 1024u)
/* 192 KiB of .bss.  A run of details is a few KiB (the worst case is a 512-entry
   module scan, ~40 KiB), so this is a ceiling, not a target: if it is ever hit the
   report says so instead of silently losing the rest. */
#define REPORT_SPOOL_SIZE   (192u * 1024u)

static char   g_Spool[REPORT_SPOOL_SIZE];
static size_t g_SpoolLen;
static bool   g_SpoolFull;      /* output had to be dropped                      */

/* Live line: straight to the card, flushed, so it survives a hang in the next probe
   step and is readable while the probe is still running. */
static void reportLive(const char *fmt, ...) {
    if (g_Out == NULL) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(g_Out, fmt, ap);
    va_end(ap);
    fputc('\n', g_Out);
    fflush(g_Out);
}

static void spoolAppend(const char *text, size_t len) {
    if (len > sizeof(g_Spool) - g_SpoolLen) { g_SpoolFull = true; return; }
    memcpy(g_Spool + g_SpoolLen, text, len);
    g_SpoolLen += len;
}

/* Details: produced exactly where the probe produced them, written later. */
static void out(const char *fmt, ...) {
    char line[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(line, sizeof(line) - 2, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if ((size_t)n > sizeof(line) - 2) n = (int)sizeof(line) - 2;
    line[n++] = '\n';
    spoolAppend(line, (size_t)n);
}

/* Called once, after the verdict: this is where the details reach the file. */
static void reportFlushDetails(void) {
    if (g_Out == NULL) return;
    if (g_SpoolLen > 0) fwrite(g_Spool, 1, g_SpoolLen, g_Out);
    if (g_SpoolFull)
        fputs("(詳細が上限に達したため、以降の詳細は省略されました)\n", g_Out);
    fflush(g_Out);
    g_SpoolLen = 0;
}

static void rec(const char *name, Result rc, u64 d0, u64 d1) {
    char line[160];
    snprintf(line, sizeof(line), "%-34s rc=0x%08X d0=0x%llX d1=0x%llX",
             name, (unsigned)rc, (unsigned long long)d0, (unsigned long long)d1);
    out("%s", line);
}

/* ---- report file: append + rotation ------------------------------------- */

/* Open `path` for appending, rotating it to "<path>.1" first when it is already
   over PROBE_LOG_MAX_BYTES.  Returns false when the path is not writable, so the
   caller can fall back to the next candidate path. */
static bool reportOpenAppend(const char *path) {
    g_Out = fopen(path, "ab");
    if (g_Out == NULL) return false;

    long size = 0;
    if (fseek(g_Out, 0, SEEK_END) == 0) size = ftell(g_Out);
    if (size > 0 && (u64)size > PROBE_LOG_MAX_BYTES) {
        char old_path[96];
        snprintf(old_path, sizeof(old_path), "%s.1", path);
        /* The previous ".1" is dropped: one old run is worth keeping for a
           comparison, more are not worth the card space. */
        fclose(g_Out);
        g_Out = NULL;
        remove(old_path);
        if (rename(path, old_path) == 0) {
            g_Out = fopen(path, "ab");
            /* Say it out loud: the file the reader is looking at starts empty, and
               the run before this one is in ".1", not gone. */
            if (g_Out != NULL) {
                reportLive("(report was over %u KiB: the previous block was rotated to %s)",
                           (unsigned)(PROBE_LOG_MAX_BYTES / 1024u), old_path);
            }
        } else {
            /* A failed rename (e.g. read-only card) must still not let the report
               grow forever, so truncate instead.  This is the only "wb" left. */
            g_Out = fopen(path, "wb");
        }
        if (g_Out == NULL) return false;
    }
    g_ReportPath = path;
    return true;
}

/* Civil date/time for a Unix timestamp, UTC.  Done by hand instead of gmtime() so
   the report does not depend on the console's timezone setting or on newlib's
   single shared gmtime buffer (Howard Hinnant's days -> civil algorithm). */
static void formatUtcIso(char *dst, size_t cap, u64 epoch) {
    const u64 secs = epoch % 86400ull;
    const u64 z    = epoch / 86400ull + 719468ull;    /* days since 0000-03-01 */
    const u64 era  = z / 146097ull;
    const u64 doe  = z % 146097ull;                   /* [0, 146096]           */
    const u64 yoe  = (doe - doe / 1460ull + doe / 36524ull - doe / 146096ull) / 365ull;
    u64 y = yoe + era * 400ull;
    const u64 doy = doe - (365ull * yoe + yoe / 4ull - yoe / 100ull);
    const u64 mp  = (5ull * doy + 2ull) / 153ull;
    const u64 d   = doy - (153ull * mp + 2ull) / 5ull + 1ull;
    const u64 m   = (mp < 10ull) ? mp + 3ull : mp - 9ull;
    if (m <= 2ull) y += 1ull;
    snprintf(dst, cap, "%04llu-%02llu-%02lluT%02llu:%02llu:%02lluZ",
             (unsigned long long)y, (unsigned long long)m, (unsigned long long)d,
             (unsigned long long)(secs / 3600ull),
             (unsigned long long)((secs / 60ull) % 60ull),
             (unsigned long long)(secs % 60ull));
}

/* ISO8601 UTC for this moment, e.g. "2026-10-26T03:17:40Z".  When time:u is not
   available (or the console clock is still at the epoch) the boot uptime is used
   rather than a wrong 1970 date: identifying the run is all the separator needs. */
static void isoNow(char *dst, size_t cap) {
    u64 ts = 0;
    if (R_SUCCEEDED(timeInitialize())) {
        const Result rc = timeGetCurrentTime(TimeType_UserSystemClock, &ts);
        timeExit();
        if (R_SUCCEEDED(rc) && ts != 0) {
            formatUtcIso(dst, cap, ts);
            return;
        }
    }
    snprintf(dst, cap, "up %llus",
             (unsigned long long)(armTicksToNs(armGetSystemTick()) / 1000000000ull));
}

/* Title id of the foreground application, 0 when nothing is running.  pm:dmnt
   answers for every running title; dmnt:cht's metadata is the fallback for the case
   where only the cheat process knows it. */
static u64 queryTitleId(void) {
    u64 pid = 0, prog = 0;
    if (R_SUCCEEDED(pmdmntGetApplicationProcessId(&pid)) && pid != 0 &&
        R_SUCCEEDED(pmdmntGetProgramId(&prog, pid)) && prog != 0) {
        return prog;
    }
    NxusProcessMetadata md;
    memset(&md, 0, sizeof(md));
    if (R_SUCCEEDED(nxusDmntGetMetadata(&md))) return md.program_id;
    return 0;
}

/* ---- 区切り / 判定 ---------------------------------------------------------
 * The separator names the run; it is written after the target wait because it
 * carries the title id, which does not exist before a title does.  The wait's own
 * "[wait ...]" lines stay attributable through the timestamp in this line.
 */
static void reportRunHeader(const char *run_iso) {
    const u32 fw = hosversionGet();
    reportLive("");
    reportLive("===== Nxus probe run %s (title 0x%016llX, fw %u.%u.%u) =====",
               run_iso, (unsigned long long)g_TitleId,
               (fw >> 16) & 0xFF, (fw >> 8) & 0xFF, fw & 0xFF);
}

/* The wait's progress lines are live (and therefore above the separator), so the
   details restate the target conclusion that the sections below depend on. */
static void reportTargetSummary(void) {
    out("");
    out("--- target -----------------------------------------------------");
    if (g_TargetFound) {
        out("  found after %llu ms (title 0x%016llX)",
            (unsigned long long)g_TargetFoundMs, (unsigned long long)g_TitleId);
    } else {
        out("  NO GAME after %u s: start a title and reload the probe.",
            TARGET_WAIT_MS / 1000u);
        out("  Everything below that needs a target is reported as 'untested',");
        out("  not as a failure.");
    }
}

/* ---- "この実行の判定" ------------------------------------------------------
 * With an appended report the newest run sits at the bottom of a file that can be
 * hundreds of KiB long, so the answer has to come before the evidence: the
 * separator, then this block, then the details (still in RAM when this runs).
 *
 * Every line is derived from a result the probes above recorded.  Anything this run
 * could not measure says 未試行 instead of inventing a verdict - "no game" is not a
 * debug-permission failure.
 */
static void reportVerdict(void) {
    const u32 fw = hosversionGet();

    reportLive("判定 (この実行):");
    if (!g_TargetFound) {
        reportLive("  対象      : ゲーム無し (%u 秒待って断念)", TARGET_WAIT_MS / 1000u);
    } else if (g_TitleId != 0) {
        reportLive("  対象      : title 0x%016llX (%llu ms で検出)",
                   (unsigned long long)g_TitleId, (unsigned long long)g_TargetFoundMs);
    } else {
        reportLive("  対象      : 検出 (%llu ms) - title id は不明",
                   (unsigned long long)g_TargetFoundMs);
    }
    reportLive("  firmware  : %u.%u.%u", (fw >> 16) & 0xFF, (fw >> 8) & 0xFF, fw & 0xFF);

    if (!g_DmntInitOk) {
        reportLive("  dmnt:cht  : initialize 失敗 rc=0x%08X", (unsigned)g_DmntInitRc);
    } else if (!g_DmntMdTried) {
        reportLive("  dmnt:cht  : 未試行 (メタデータ取得まで到達せず)");
    } else if (R_FAILED(g_DmntMdRc)) {
        reportLive("  dmnt:cht  : 失敗 rc=0x%08X", (unsigned)g_DmntMdRc);
    } else {
        reportLive("  dmnt:cht  : metadata OK (pid=0x%llX)", (unsigned long long)g_Pid);
    }

    if (!g_DbgTried) {
        reportLive("  デバッグ  : 未実行 (対象なし)");
    } else if (R_FAILED(g_DbgRc)) {
        reportLive("  デバッグ  : svcDebugActiveProcess 失敗 rc=0x%08X", (unsigned)g_DbgRc);
    } else {
        reportLive("  デバッグ  : svcDebugActiveProcess OK (pid=0x%llX)",
                   (unsigned long long)g_Pid);
    }

    if (!g_DbgTried || R_FAILED(g_DbgRc)) {
        reportLive("  HWBP      : 未試行 (デバッグセッションが無い)");
        reportLive("  例外配達  : 未試行");
    } else {
        reportLive("  HWBP      : %u/%u 語を受理 (却下 %u)",
                   (unsigned)g_HwbpAccepted,
                   (unsigned)(g_HwbpAccepted + g_HwbpRejected), (unsigned)g_HwbpRejected);
        reportLive("  例外配達  : 命令BP %u / データBP %u%s",
                   (unsigned)g_ExecDelivered, (unsigned)g_DataDelivered,
                   (g_ExecDelivered + g_DataDelivered) == 0 ? "  <- 配達ゼロ" : "");
    }

    if (!g_PerCoreTested) {
        reportLive("  コア別BP  : 未試行 (デバッグセッション未確立)");
    } else if (g_PerCoreFailures == 0) {
        reportLive("  コア別BP  : 確認済み (4コアの移行と書き込みが全て成功)");
    } else {
        reportLive("  コア別BP  : 未確認 (移行/書き込み失敗 %u 件, last rc=0x%08X)",
                   (unsigned)g_PerCoreFailures, (unsigned)g_LastCoreMigrateRc);
    }

    if (!g_HidTried) {
        reportLive("  HID       : 未試行");
    } else if (R_SUCCEEDED(g_HidRc)) {
        reportLive("  HID       : 読めた (buttons 0x%08llX)",
                   (unsigned long long)g_HidButtons);
    } else {
        reportLive("  HID       : 読めない rc=0x%08X", (unsigned)g_HidRc);
    }

    if (!g_TargetFound) {
        reportLive("  総合      : 対象なし - ゲームを起動して再実行 "
                   "(この run の「未試行」は失敗ではない)");
    } else if (!g_DbgTried || R_FAILED(g_DbgRc)) {
        reportLive("  総合      : デバッガを掴めなかった - NPDM のデバッグ権限と "
                   "kernel 設定を確認");
    } else if ((g_ExecDelivered + g_DataDelivered) == 0) {
        reportLive("  総合      : アタッチ成功・HWBP は受理されたが例外は届かず");
    } else {
        reportLive("  総合      : アタッチ成功・例外配達あり (命令 %u / データ %u)",
                   (unsigned)g_ExecDelivered, (unsigned)g_DataDelivered);
    }
    reportLive("");
}

/* ---- optional target addresses from SD ---------------------------------- */

static void loadTargets(void) {
    g_ExecTarget  = g_MainBase;
    /* 0 means "no address given": probeDelivery() then watches a live stack slot,
       which is far more likely to be written than the start of the heap. */
    g_WatchTarget = 0;

    FILE *f = fopen(PROBE_CFG_FILE, "rb");
    if (f == NULL) return;
    char buf[128] = {0};
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    (void)n;
    /* "exec=<hex> watch=<hex>" */
    char *p = strstr(buf, "exec=");
    if (p != NULL) g_ExecTarget = strtoull(p + 5, NULL, 16);
    p = strstr(buf, "watch=");
    if (p != NULL) g_WatchTarget = strtoull(p + 6, NULL, 16);
    out("targets from SD: exec=0x%llX watch=0x%llX",
        (unsigned long long)g_ExecTarget, (unsigned long long)g_WatchTarget);
}

/* ---- dmnt:cht ----------------------------------------------------------- */

static void probeDmnt(void) {
    out("");
    out("--- dmnt:cht ---------------------------------------------------");

    Result rc = nxusDmntInitialize();
    rec("dmnt:cht initialize", rc, 0, 0);
    g_DmntInitRc = rc;
    g_DmntInitOk = R_SUCCEEDED(rc);
    if (R_FAILED(rc)) return;

    bool has = false;
    rc = nxusDmntHasCheatProcess(&has);
    rec("HasCheatProcess", rc, has ? 1 : 0, 0);

    if (R_SUCCEEDED(rc) && !has) {
        rc = nxusDmntForceOpen();
        rec("ForceOpenCheatProcess", rc, 0, 0);
        svcSleepThread(100000000ull);
    }

    NxusProcessMetadata md;
    memset(&md, 0, sizeof(md));
    rc = nxusDmntGetMetadata(&md);
    rec("GetCheatProcessMetadata", rc, md.process_id, md.program_id);
    /* Recorded for the verdict block, which cannot look at this text: it is written
       before the details reach the file. */
    g_DmntMdTried = true;
    g_DmntMdRc = rc;
    if (R_SUCCEEDED(rc)) {
        g_Pid      = md.process_id;
        g_MainBase = md.main_nso_base;
        g_MainSize = md.main_nso_size;
        g_HeapBase = md.heap_base;
        g_HeapSize = md.heap_size;
        out("  main nso : 0x%llX + 0x%llX", (unsigned long long)md.main_nso_base,
            (unsigned long long)md.main_nso_size);
        out("  heap     : 0x%llX + 0x%llX", (unsigned long long)md.heap_base,
            (unsigned long long)md.heap_size);
        out("  alias    : 0x%llX + 0x%llX", (unsigned long long)md.alias_base,
            (unsigned long long)md.alias_size);
        out("  aslr     : 0x%llX + 0x%llX", (unsigned long long)md.aslr_base,
            (unsigned long long)md.aslr_size);
        out("  build id : %02X%02X%02X%02X %02X%02X%02X%02X",
            md.main_nso_build_id[0], md.main_nso_build_id[1], md.main_nso_build_id[2],
            md.main_nso_build_id[3], md.main_nso_build_id[4], md.main_nso_build_id[5],
            md.main_nso_build_id[6], md.main_nso_build_id[7]);
        /* The title's bitness comes from its ADDRESS SPACE, not from the NSO size:
           an NSO is always well below 4 GiB, so the old
           main_nso_size > 4 GiB test printed "32-bit title" for every title,
           AArch64 included.  Both values are shown: the derived arch (the same
           rule the pointer scan uses, from aslr_base/aslr_size) and the NSO size
           it was NOT derived from, so a surprising pair is visible in the report
           instead of being hidden behind a wrong label. */
        const NxusPtrScanArch arch =
            nxusPtrScanArchFromAddressSpace(md.aslr_base, md.aslr_size);
        const char *arch_name = (arch == NXUS_PTRSCAN_ARCH_AARCH64) ? "AArch64"
                              : (arch == NXUS_PTRSCAN_ARCH_AARCH32) ? "AArch32"
                              : "unknown";
        out("  arch     : %s (addr space), NSO size 0x%llX",
            arch_name, (unsigned long long)md.main_nso_size);
    }

    u64 count = 0;
    rc = nxusDmntGetMappingCount(&count);
    rec("GetCheatProcessMappingCount", rc, count, 0);

    if (R_SUCCEEDED(rc) && count > 0) {
        u32 want = (count > MAX_MAPPINGS) ? MAX_MAPPINGS : (u32)count;
        NxusMemoryInfo *maps = (NxusMemoryInfo *)malloc(want * sizeof(NxusMemoryInfo));
        size_t got = 0;
        rc = nxusDmntGetMappings(maps, want, 0, &got);
        rec("GetCheatProcessMappings", rc, got, 0);

        if (R_SUCCEEDED(rc)) {
            u32 readable = 0, executable = 0, modules = 0;
            u8 page[0x200];
            for (size_t i = 0; i < got; i++) {
                if (maps[i].perm & NXUS_PERM_R) readable++;
                if (maps[i].perm & NXUS_PERM_X) executable++;
                /* module detection: MOD0 lives in the first page of a module */
                if ((maps[i].perm & NXUS_PERM_R) && maps[i].size >= sizeof(page) &&
                    R_SUCCEEDED(nxusDmntRead(maps[i].base_addr, page, sizeof(page)))) {
                    for (u32 off = 0; off + 4 <= sizeof(page); off += 4) {
                        if (memcmp(page + off, "MOD0", 4) == 0) {
                            modules++;
                            out("  module: base=0x%llX size=0x%llX mod0=+0x%X id=%02X%02X%02X%02X",
                                (unsigned long long)maps[i].base_addr,
                                (unsigned long long)maps[i].size, off,
                                page[0x40], page[0x41], page[0x42], page[0x43]);
                            break;
                        }
                    }
                }
            }
            out("  mappings: %zu read=%u exec=%u modules=%u",
                got, readable, executable, modules);
            rec("ModuleScan", 0, modules, 0);
        }
        free(maps);
    }

    if (g_MainBase != 0) {
        u8 head[0x10];
        rc = nxusDmntRead(g_MainBase, head, sizeof(head));
        rec("ReadCheatProcessMemory(main)", rc, 0, 0);
    }
}

/* ---- hardware breakpoint candidate matrix ------------------------------- */

typedef struct {
    const char *name;
    u32 slot;
    u64 ctrl;
    int use_watch_target;
} HwbpCandidate;

/* ctrl words: E is bit0, BAS bits 5-12, LINK bits 16-19, BT bits 20-23.
   The kernel masks the user bits (bp 0x7F01E1 / wp 0xFF0F1FF9) and ORs in its
   own security bits (bp 0x4004 / wp 0x104004), per switchbrew's SVC page.
   The words below are the ones the product arms: an execution breakpoint MUST be
   linked to the context-id breakpoint in slot 5 (BT = 0b0001, LBN = 5), otherwise
   the kernel answers ResultInvalidCombination (0xE801). */
static const HwbpCandidate g_Candidates[] = {
    { "bp ctxid slot5 (link source)",   0x05, HWBP_CTX_LINK5,   0 },
    { "bp exec slot0 plain",            0x00, 0x000001E1ull,    0 },  /* expect 0xE801 */
    { "bp exec slot0 linked LBN=5",     0x00, HWBP_EXEC_LINK5,  0 },
    { "wp store-4B slot0x10 no link",   0x10, 0x000001F1ull,    1 },
    { "wp store-4B slot0x10 link5",     0x10, 0x000501F1ull,    1 },
    { "wp access-4B slot0x11 link5",    0x11, 0x000501F9ull,    1 },
};

static void probeHardwareBreakpoints(void) {
    for (unsigned i = 0; i < sizeof(g_Candidates) / sizeof(g_Candidates[0]); i++) {
        const HwbpCandidate *c = &g_Candidates[i];
        /* DBGWVR/DBGBVR must hold an aligned word: the byte mask is in BAS, and an
           unaligned value (bit0-2 set) loses the high BAS bits and never fires. */
        u64 value = c->use_watch_target ? (g_WatchTarget & ~7ull) : (g_ExecTarget & ~3ull);
        Result rc = setHwBpAllCores(c->slot, c->ctrl, value);
        rec(c->name, rc, c->slot, value);
        if (R_SUCCEEDED(rc)) g_HwbpAccepted++;
        else                 g_HwbpRejected++;
        /* Clear immediately (E=0), except for the context-id link source: keeping
           slot 5 armed is what makes the linked-execution candidate below a
           representative test of the product's configuration. */
        if (c->slot != 0x05) setHwBpAllCores(c->slot, 0, 0);
    }
    setHwBpAllCores(0x05, 0, 0);
}

/* Are hardware breakpoints per-core on this kernel?  Set the same breakpoint
   from a thread pinned to each core and report the result. */
typedef struct { int core; Result rc; u64 after; } CoreResult;
static CoreResult g_CoreResults[4];

static void coreThread(void *arg) {
    CoreResult *r = (CoreResult *)arg;
    r->rc = svcSetHardwareBreakPoint(0, 0x000001E1ull, g_ExecTarget);
    svcSetHardwareBreakPoint(0, 0, 0);
}

static void probePerCore(void) {
    alignas(0x1000) static u8 stacks[4][0x4000];
    g_PerCoreTested = true;
    for (int core = 0; core < 4; core++) {
        Thread t;
        g_CoreResults[core].core = core;
        g_CoreResults[core].rc = 0xDEAD;
        Result rc = threadCreate(&t, coreThread, &g_CoreResults[core], stacks[core],
                                 sizeof(stacks[core]), 0x2C, core);
        if (R_FAILED(rc)) {
            /* The per-core question was not measured on this core at all, so the
               verdict below must not claim it was. */
            rec("per-core thread create", rc, (u64)core, 0);
            g_PerCoreFailures++;
            g_LastCoreMigrateRc = rc;
            continue;
        }
        threadStart(&t);
        threadWaitForExit(&t);
        threadClose(&t);
        rec("svcSetHardwareBreakPoint", g_CoreResults[core].rc, (u64)core, 0);
        /* The write itself can fail even when the migration worked.  Counting it
           keeps the verdict honest: "confirmed" must mean four successful writes,
           not four attempted ones. */
        if (R_FAILED(g_CoreResults[core].rc)) {
            g_PerCoreFailures++;
            g_LastCoreMigrateRc = g_CoreResults[core].rc;
        }
    }
}

/* The "are breakpoints per-core?" answer is ONLY meaningful if the four core
   migrations actually happened: a failed svcSetThreadCoreMask leaves the caller on
   the previous core, so all four writes land in the same registers and every core
   reports the same value.  Saying "confirmed" then would be a lie that the day-1
   hardware decision is based on, so the verdict is downgraded instead. */
static void reportPerCoreVerdict(void) {
    if (g_PerCoreFailures == 0) {
        out("コア別BP=確認済み (all 4 core migrations and per-core writes succeeded)");
    } else {
        out("コア別BP=未確認（移行失敗） (%u core test(s) failed, last rc=0x%08X)",
            (unsigned)g_PerCoreFailures, (unsigned)g_LastCoreMigrateRc);
        out("  -> the per-core results above are NOT evidence: some writes went to the "
            "wrong core");
    }
}

/* ---- kernel debug session ----------------------------------------------- */

static void probeDelivery(Handle dbg, u64 thread_id, u64 pc, u64 sp);
static void probeDmntReadSizes(void);

static void probeDebugSession(void) {
    if (g_Pid == 0) {
        /* Do NOT close the cheat process here: with no game to attach to we would
           leave dmnt closed for the rest of the boot, so a game started later
           would run with its own cheats dead. */
        /* No synthesised Result here: printing a fake error code made the report
           look like an NPDM permission failure when the real cause is "no target". */
        out("  svcDebugActiveProcess: NOT RUN - no process id (start a game first)");
        out("  -> this is NOT a debug-permission failure; nothing could be tested");
        return;
    }

    Result rc = nxusDmntForceClose();
    rec("ForceCloseCheatProcess", rc, 0, 0);
    svcSleepThread(200000000ull);

    Handle dbg = INVALID_HANDLE;
    rc = svcDebugActiveProcess(&dbg, g_Pid);
    rec("svcDebugActiveProcess", rc, g_Pid, 0);
    g_DbgTried = true;
    g_DbgRc = rc;
    if (R_FAILED(rc)) {
        nxusDmntForceOpen();
        return;
    }

    /* The process is stopped right now.  Drain events and continue every
       thread; capture the first thread context we can. */
    u32 create_process = 0, create_thread = 0, exceptions = 0, other = 0;
    u64 first_thread = 0;
    int got_context = 0;

    for (u32 i = 0; i < 4096; i++) {
        DebugEventInfo ev;
        rc = svcGetDebugEvent(&ev, dbg);
        if (R_FAILED(rc)) break;

        switch (ev.type) {
            case DebugEventType_CreateProcess: create_process++; break;
            case DebugEventType_CreateThread:
                create_thread++;
                if (first_thread == 0) first_thread = ev.thread_id;
                break;
            case DebugEventType_Exception:     exceptions++; break;
            default:                           other++; break;
        }

        if (!got_context && ev.thread_id != 0) {
            ThreadContext ctx;
            memset(&ctx, 0, sizeof(ctx));
            Result crc = svcGetDebugThreadContext(&ctx, dbg, ev.thread_id, RegisterGroup_CpuAll);
            rec("svcGetDebugThreadContext", crc, ev.thread_id, 0);
            if (R_SUCCEEDED(crc)) {
                got_context = 1;
                out("  pc=0x%llX lr=0x%llX sp=0x%llX psr=0x%08X",
                    (unsigned long long)ctx.pc.x, (unsigned long long)ctx.lr,
                    (unsigned long long)ctx.sp, (unsigned)ctx.psr);
                out("  AArch32 view: r0=0x%08X r1=0x%08X r2=0x%08X r3=0x%08X",
                    ctx.cpu_gprs[0].r, ctx.cpu_gprs[1].r, ctx.cpu_gprs[2].r, ctx.cpu_gprs[3].r);
            }
        }

        /* continue exactly the thread that produced this event
           (3.0.0+ form takes an explicit thread list) */
        /* 4|2|1 = ContinueAll | ContinueOthers | IgnoreException: the form the working
           reference (noexs, server/source/noexs/source/debug.cpp:74) uses on hardware. */
        svcContinueDebugEvent(dbg, 4u | 2u | 1u, &ev.thread_id, 1);
    }

    rec("debug events", 0, create_process, create_thread);
    rec("debug exceptions", 0, exceptions, other);

    /* v2: prove that exceptions are actually DELIVERED, and measure dmnt reads */
    {
        u64 ids[8];
        s32 num = 0;
        Result lrc = svcGetThreadList(&num, ids, 8, dbg);
        rec("svcGetThreadList", lrc, (u64)num, 0);
        u64 tid = first_thread;
        if (R_SUCCEEDED(lrc) && num > 0) tid = ids[0];
        if (tid != 0) {
            ThreadContext ctx;
            memset(&ctx, 0, sizeof(ctx));
            if (R_SUCCEEDED(svcGetDebugThreadContext(&ctx, dbg, tid, RegisterGroup_CpuAll))) {
                probeDelivery(dbg, tid, ctx.pc.x, ctx.sp);
            }
        }
    }

    /* now that threads are running, try the breakpoint matrix */
    probeHardwareBreakpoints();
    probePerCore();
    reportPerCoreVerdict();

    /* closing the debug handle detaches and resumes the target */
    svcCloseHandle(dbg);
    out("debug session closed (target resumed)");

    svcSleepThread(100000000ull);
    rc = nxusDmntForceOpen();
    rec("ForceOpenCheatProcess (restore)", rc, 0, 0);
}

/* Can a sysmodule read the controller at all?  This is what decides whether the
   hotkey (freeze without touching the PC) is possible on retail hardware. */
/* ---- watchpoint DELIVERY -------------------------------------------------
 * The candidate matrix above only proves the kernel ACCEPTED a control word.
 * The question that decides whether "who writes this address" can ever work is
 * whether the session actually RECEIVES exceptions.  This arms a breakpoint,
 * lets the target run, and counts what comes back.
 *
 * It also measures how large a single dmnt read may be and how fast it goes,
 * which sets the PC-side scanner's chunk size.
 */

/* Drain events for up to ~timeout_ms, returning how many exceptions arrived.
   Every event is continued immediately so the target keeps running. */
typedef struct {
    u32 instruction_bp;      /* BreakPointType_HardwareInstruction (execute) */
    u32 data_bp;             /* BreakPointType_HardwareData (watchpoint)      */
    u32 other_exceptions;
    u64 first_address;
    u64 first_thread;
    u64 first_pc;
    u64 first_lr;
} DeliveryCount;

static u32 deliverLoop(Handle dbg, u32 timeout_ms, DeliveryCount *out) {
    DeliveryCount count;
    memset(&count, 0, sizeof(count));
    u64 deadline = armTicksToNs(armGetSystemTick()) / 1000000ull + timeout_ms;

    while (armTicksToNs(armGetSystemTick()) / 1000000ull < deadline) {
        DebugEventInfo ev;
        if (R_FAILED(svcGetDebugEvent(&ev, dbg))) {
            svcSleepThread(2000000ull);          /* 2 ms: let the target run */
            continue;
        }
        if (ev.type == DebugEventType_Exception) {
            const u32 kind = (u32)ev.info.exception.type;                     /* DebugException */
            const u32 bp   = (u32)ev.info.exception.specific.break_point.type; /* BreakPointType */
            if (kind == (u32)DebugException_BreakPoint) {
                if (bp == (u32)BreakPointType_HardwareInstruction) count.instruction_bp++;
                else count.data_bp++;
                if (count.first_address == 0) {
                    count.first_address = (u64)ev.info.exception.specific.break_point.address;
                    count.first_thread = ev.thread_id;
                    ThreadContext ctx;
                    memset(&ctx, 0, sizeof(ctx));
                    if (R_SUCCEEDED(svcGetDebugThreadContext(&ctx, dbg, ev.thread_id,
                                                             RegisterGroup_CpuAll))) {
                        count.first_pc = ctx.pc.x;
                        count.first_lr = ctx.lr;
                    }
                }
            } else {
                count.other_exceptions++;
            }
        }
        /* ContinueFlag_ContinueAll: the per-thread form returns ResultBusy while
           any event is still queued, which would leave threads suspended and make
           the whole delivery test meaningless. */
        svcContinueDebugEvent(dbg, 4u | 2u | 1u, NULL, 0);
    }
    if (out != NULL) *out = count;
    return count.instruction_bp + count.data_bp;
}

static void probeDelivery(Handle dbg, u64 thread_id, u64 pc, u64 sp) {
    out("");
    out("--- watchpoint DELIVERY (does an exception actually arrive?) ---");

    /* An E=1 instruction breakpoint is only legal when it is linked to a context
       (otherwise the kernel returns InvalidCombination, 0xE801), and a ContextID
       breakpoint takes the DEBUG HANDLE as its value - the kernel substitutes
       the process id.  Arm that link source in slot 5 first. */
    /* The first word is exactly what the product arms (nxus_debug.c uses
       HWBP_CTX_LINK5): a probe that tests a different control word can report
       "not delivered" for a word the product never uses.  The second is kept as a
       comparison so the day-1 report still shows why it was rejected. */
    static const struct { const char *label; u64 ctrl; } ctx_words[] = {
        { "BT=0b0011 LINKED_CONTEXT_IDR_MATCH (product word)", HWBP_CTX_LINK5 },
        { "BT=0b0100 (previous product value)",                0x004001E1ull },
    };
    u64 CTRL_CTX_BP = 0;          /* the word that actually delivered, for the WP test */
    Result rc = 0;
    for (unsigned i = 0; i < sizeof(ctx_words) / sizeof(ctx_words[0]); i++) {
        out("  candidate %u: %s", i + 1, ctx_words[i].label);
        rc = setHwBpAllCores(0x05, ctx_words[i].ctrl, (u64)dbg);
        rec("  link source in slot 5", rc, ctx_words[i].ctrl, (u64)dbg);
        if (R_FAILED(rc)) continue;

        /* Cortex-A57 slots 0-3 are address breakpoints (only 4-5 are context-aware).
           Try the product's linked instruction address breakpoint at pc in slot 0;
           if rejected, fall back to the context word itself. */
        u64 exec_ctrl = HWBP_EXEC_LINK5;
        u64 exec_val  = pc & ~3ull;
        rc = setHwBpAllCores(0x00, exec_ctrl, exec_val);
        if (R_FAILED(rc)) {
            exec_ctrl = ctx_words[i].ctrl;
            exec_val  = (u64)dbg;
            rc = setHwBpAllCores(0x00, exec_ctrl, exec_val);
        }
        rec("  control exec bp in slot 0", rc, exec_ctrl, exec_val);
        if (R_SUCCEEDED(rc)) {
            DeliveryCount count;
            memset(&count, 0, sizeof(count));
            u32 got = deliverLoop(dbg, 400, &count);
            /* Totals for the verdict: "accepted" and "actually delivered" are the two
               answers this probe exists for and they differ, so count both kinds. */
            g_ExecDelivered += count.instruction_bp;
            g_DataDelivered += count.data_bp;
            rec("  exceptions delivered", 0, count.instruction_bp, count.other_exceptions);
            if (got > 0) {
                out("    delivered: %u (exec=%u other=%u) pc=0x%llX lr=0x%llX thread=%llu",
                    got, count.instruction_bp, count.other_exceptions,
                    (unsigned long long)count.first_pc, (unsigned long long)count.first_lr,
                    (unsigned long long)count.first_thread);
                if (CTRL_CTX_BP == 0) {
                    CTRL_CTX_BP = ctx_words[i].ctrl;
                    out("    -> this word delivers; the watchpoint test below uses it");
                }
            } else {
                out("    NO exception: this word is accepted but does not deliver");
            }
            setHwBpAllCores(0x00, 0, 0);
        }
    }
    if (CTRL_CTX_BP == 0) {
        CTRL_CTX_BP = ctx_words[0].ctrl;
        out("  neither candidate delivered: the watchpoint test below uses candidate 1");
        out("  (check the rc lines above: a rejected arm explains it)");
    }
    /* Re-arm slot 5 with the chosen CTRL_CTX_BP (the loop above ended on the last
       candidate, which would otherwise stay in slot 5 during the watchpoint tests). */
    setHwBpAllCores(0x05, CTRL_CTX_BP, (u64)dbg);

    /* write watchpoint on the stack slot the target is most likely to touch.
       AN ALIGNED WORD is mandatory: BAS carries the byte mask, and an unaligned
       DBGWVR value (e.g. ...DC4, bit2 set) makes the kernel ignore BAS[7:4] so the
       watchpoint never fires.  The offset still has to be mirrored in the ctrl BAS
       for a watch to start mid-word; g_WatchTarget & ~7 watches the containing word. */
    u64 watch = (sp - 8) & ~7ull;
    if (g_WatchTarget != 0) {
        /* the user gave us a real address (probe_target.txt): watch that instead
           of a stack slot nobody may touch, which yields 0 either way */
        watch = g_WatchTarget & ~7ull;
        out("  watch address: 0x%llX (from probe_target.txt)", (unsigned long long)watch);
    } else {
        out("  watch address: 0x%llX (sp-8; slot 5 stays armed as its link source)",
            (unsigned long long)watch);
    }

    static const struct { const char *name; u32 slot; u64 ctrl; } tries[] = {
        { "wp store-4B slot0x10 no link", 0x10, 0x000001F1ull },
        { "wp store-4B slot0x10 link5",   0x10, 0x000501F1ull },
        { "wp access-4B slot0x11 link5",  0x11, 0x000501F9ull },
    };
    for (unsigned i = 0; i < sizeof(tries) / sizeof(tries[0]); i++) {
        rc = setHwBpAllCores(tries[i].slot, tries[i].ctrl, watch);
        DeliveryCount count;
        memset(&count, 0, sizeof(count));
        u32 got = 0;
        if (R_SUCCEEDED(rc)) {
            got = deliverLoop(dbg, 800, &count);      /* longer: a stack write may be rare */
            g_ExecDelivered += count.instruction_bp;
            g_DataDelivered += count.data_bp;
        }
        rec(tries[i].name, rc, count.data_bp, watch);
        if (R_SUCCEEDED(rc)) {
            out("  -> watchpoint exceptions: %u (other=%u)%s", count.data_bp,
                count.other_exceptions, count.data_bp > 0 ? "   <== WATCHPOINTS DELIVER" : "");
            if (count.data_bp > 0) {
                out("     first data breakpoint at 0x%llX thread=%llu",
                    (unsigned long long)count.first_address, (unsigned long long)count.first_thread);
            }
            (void)got;
        }
        setHwBpAllCores(tries[i].slot, 0, 0);
    }
    setHwBpAllCores(0x05, 0, 0);
    (void)thread_id;
}

static void probeDmntReadSizes(void) {
    out("");
    out("--- dmnt read size / speed (sets the PC scanner's chunk size) ---");

    if (g_MainBase == 0) {
        out("  (no target: read sizes untested)");
        return;
    }

    static u8 buffer[4 * 1024 * 1024];
    static const u32 sizes[] = { 4096, 32768, 131072, 262144, 524288, 1048576, 2097152, 4194304 };

    for (unsigned i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        u32 size = sizes[i];
        Result rc = nxusDmntRead(g_MainBase, buffer, size);
        if (R_FAILED(rc)) {
            rec("ReadCheatProcessMemory size", rc, size, 0);
            out("  %7u bytes: REJECTED", size);
            continue;
        }
        u64 start = armTicksToNs(armGetSystemTick());
        const int rounds = 5;
        for (int r = 0; r < rounds; r++) {
            nxusDmntRead(g_MainBase, buffer, size);
        }
        u64 elapsed_ns = armTicksToNs(armGetSystemTick()) - start;
        double ms = (double)elapsed_ns / 1000000.0 / rounds;
        double mbps = ms > 0.0 ? ((double)size / (1024.0 * 1024.0)) / (ms / 1000.0) : 0.0;
        rec("ReadCheatProcessMemory size", 0, size, (u64)ms);
        out("  %7u bytes: ok   %7.2f ms/read   %6.1f MB/s", size, ms, mbps);
    }
}

static void probeHid(void) {
    out("");
    out("--- HID / hotkey -----------------------------------------------");

    u64 buttons = 0;
    Result rc = nxusHidReadOnce(&buttons);
    g_HidTried = true;
    g_HidRc = rc;
    g_HidButtons = buttons;
    rec("hidInitialize + pad read", rc, buttons, 0);
    if (R_SUCCEEDED(rc)) {
        out("  buttons held right now: 0x%08llX", (unsigned long long)buttons);
        out("  (hold a button while the probe runs to see it here)");
    } else {
        out("  a sysmodule cannot read the controller on this setup");
        out("  -> the hotkey feature needs another route (see docs/HOTKEY.md)");
    }
}

/* Wait until a title is up: this sysmodule is loaded by boot2, where no game runs
 * yet, and every interesting probe needs one.
 *
 * This is the wait that used to be 120 s long, and it is NOT a wait for other
 * modules: everything the probe needs (sm/setsys/fs/dmnt/pm) is initialized
 * synchronously in __appInit() before this function is reached, so sleeping here
 * makes nothing "ready".  It waits for the *user* to start a title, which is worth
 * TARGET_WAIT_MS at most - after that the rest of the probe runs anyway and reports
 * the target-dependent parts as untested, instead of parking the report for two
 * minutes on every boot.
 *
 * Its progress is written live (reportLive): this is the one place where the probe
 * can spend 30 s before producing its first detail line.
 */
static bool waitForTarget(u32 timeout_ms, const char *run_iso) {
    const u64 start = armTicksToNs(armGetSystemTick()) / 1000000ull;
    u32 last_note = 0xFFFFFFFFu;
    u32 last_open = 0xFFFFFFFFu;
    bool announced = false;

    for (;;) {
        const u64 elapsed = armTicksToNs(armGetSystemTick()) / 1000000ull - start;
        bool found = false;

        bool has = false;
        if (R_SUCCEEDED(nxusDmntHasCheatProcess(&has)) && has) found = true;

        /* A running title is visible through pm:dmnt even before its cheat process
           exists, so this is the reliable "a game is up" signal. */
        u64 app_pid = 0;
        if (!found && R_SUCCEEDED(pmdmntGetApplicationProcessId(&app_pid)) && app_pid != 0) {
            reportLive("[wait +%llu s] foreground application pid=0x%llX",
                       (unsigned long long)(elapsed / 1000ull), (unsigned long long)app_pid);
            found = true;
        }

        if (found) {
            /* Recorded for the verdict block, which needs the title and the wait. */
            g_TargetFound = true;
            g_TargetFoundMs = elapsed;
            g_TitleId = queryTitleId();
            reportLive("[wait +%llu s] target found (title 0x%016llX)",
                       (unsigned long long)(elapsed / 1000ull), (unsigned long long)g_TitleId);
            return true;
        }

        /* The wait happens before the run separator (the separator carries the title
           id, which does not exist until a title does), so it stamps its own lines
           with this run's timestamp. */
        if (!announced) {
            announced = true;
            reportLive("--- %s: waiting up to %u s for a title ---",
                       run_iso, timeout_ms / 1000u);
        }

        /* Titles that are not auto-attached never report a cheat process, so ask
           dmnt to open one for the foreground application.  This has to be retried
           while we wait: at t=0 there is no game yet, and the user may start one
           15 seconds later.  probeDebugSession() closes it again. */
        const u64 seconds = elapsed / 1000ull;
        if ((u32)seconds != last_open && (seconds % 5ull) == 0ull) {
            last_open = (u32)seconds;
            Result orc = nxusDmntForceOpen();
            if (R_SUCCEEDED(orc)) {
                reportLive("[wait +%llu s] opened the cheat process "
                           "(ForceOpenCheatProcess)", (unsigned long long)seconds);
            }
        }

        if (elapsed >= timeout_ms) {
            reportLive("[wait +%llu s] no game - giving up on the target wait",
                       (unsigned long long)seconds);
            return false;
        }

        if (elapsed / 5000ull != last_note) {        /* every 5 s, and live */
            last_note = (u32)(elapsed / 5000ull);
            reportLive("[wait +%llu s] no target yet - start a game "
                       "(giving up at %u s)",
                       (unsigned long long)seconds, timeout_ms / 1000u);
        }
        svcSleepThread(500000000ull);                /* 500 ms */
    }
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;

    /* The whole point of the probe is this file, so make several attempts at a path
       that works: sdmc:/nxus may be unwritable (or the card read-only), and a silently
       missing report would look like "the probe did nothing".
       The report is opened for APPENDING - and rotated when it is full, see
       reportOpenAppend() - so each run leaves its own block behind instead of
       erasing the run it is meant to be compared with. */
    mkdir("sdmc:/nxus", 0777);
    static const char *const log_paths[] = {
        PROBE_LOG_FILE,
        "sdmc:/probe.txt",
        "sdmc:/switch/probe.txt",     /* always present on an Atmosphère card */
    };
    unsigned used_path = 0;
    for (; used_path < sizeof(log_paths) / sizeof(log_paths[0]); used_path++) {
        if (reportOpenAppend(log_paths[used_path])) break;
    }
    /* Before anything else: on a fallback path the reader has to know that
       sdmc:/nxus/probe.txt is not the file this run wrote. */
    if (g_Out != NULL && used_path != 0) {
        reportLive("(report written to %s - the preferred path was not writable)",
                   log_paths[used_path]);
    }

    /* Written and flushed immediately: if this file is missing after a reboot the
       sysmodule simply did not run (boot2 not honoured / not the emuMMC that has it),
       which is otherwise indistinguishable from "it ran but produced no output". */
    {
        static const char *const markers[] = { "sdmc:/nxus/probe_started.txt",
                                               "sdmc:/probe_started.txt" };
        for (unsigned i = 0; i < sizeof(markers) / sizeof(markers[0]); i++) {
            /* Rotate the previous run's marker first: the file only means "this
               boot wrote it" if it was not left behind by an older run. */
            {
                char prev[96];
                snprintf(prev, sizeof(prev), "%s.1", markers[i]);
                remove(prev);
                rename(markers[i], prev);
            }
            FILE *m = fopen(markers[i], "wb");
            if (m == NULL) continue;
            u32 v = hosversionGet();
            fprintf(m, "probe sysmodule started\nbuild: %s %s\nfirmware: %u.%u.%u\n",
                    __DATE__, __TIME__, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF);
            fclose(m);
            break;
        }
    }

    /* Timestamp of this run.  The header line is written after the target wait
       (it carries the title id), so the time is taken here, where the run starts. */
    char run_iso[32];
    isoNow(run_iso, sizeof(run_iso));

    /* 30 s instead of 120 s: see waitForTarget().  Its progress goes to the report
       live, so a boot that is stuck in the wait is visible on the card. */
    (void)waitForTarget(TARGET_WAIT_MS, run_iso);
    if (g_TitleId == 0) g_TitleId = queryTitleId();

    /* 区切り -> 判定 -> 詳細.  Only the first two are written to the card now; the
       details are still in RAM and follow reportVerdict() at the end of main(). */
    reportRunHeader(run_iso);

    out("(probe build: %s %s)", __DATE__, __TIME__);
    reportTargetSummary();

    /* dmnt:cht was opened in __appInit(); now that waitForTarget() has seen a
       running game (or timed out), query its metadata, mappings and modules. */
    probeDmnt();

    probeDmntReadSizes();
    loadTargets();

    probeHid();

    out("");
    out("--- debug session + breakpoints --------------------------------");
    probeDebugSession();

    out("");
    out("--- done.  copy the newest block of %s back to the PC ---------",
        (g_ReportPath != NULL) ? g_ReportPath : "probe.txt");

    /* Verdict first, details second: the report is append-only, so the verdict is
       written while the details are still in RAM. */
    reportVerdict();
    reportFlushDetails();

    if (g_Out != NULL) fclose(g_Out);
    g_Out = NULL;

    while (true) {
        svcSleepThread(1000000000ull);
    }
    return 0;
}
