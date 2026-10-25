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

u32 __nx_applet_type = AppletType_None;
u32 __nx_fs_num_sessions = 1;

#define INNER_HEAP_SIZE (2u * 1024 * 1024)
#define PROBE_LOG_FILE  "sdmc:/nxus/probe.txt"
#define PROBE_CFG_FILE  "sdmc:/nxus/probe_target.txt"
#define MAX_MAPPINGS    512

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

static void out(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    if (g_Out != NULL) { vfprintf(g_Out, fmt, ap); fputc('\n', g_Out); fflush(g_Out); }
    va_end(ap);
}

static void rec(const char *name, Result rc, u64 d0, u64 d1) {
    char line[160];
    snprintf(line, sizeof(line), "%-34s rc=0x%08X d0=0x%llX d1=0x%llX",
             name, (unsigned)rc, (unsigned long long)d0, (unsigned long long)d1);
    out("%s", line);
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
    Result rc = nxusDmntInitialize();
    rec("dmnt:cht initialize", rc, 0, 0);
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
        out("  build id : %02X%02X%02X%02X %02X%02X%02X%02X (%s)",
            md.main_nso_build_id[0], md.main_nso_build_id[1], md.main_nso_build_id[2],
            md.main_nso_build_id[3], md.main_nso_build_id[4], md.main_nso_build_id[5],
            md.main_nso_build_id[6], md.main_nso_build_id[7],
            (md.main_nso_size > 0x100000000ull) ? "64-bit title" : "32-bit title");
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
    rec("hidInitialize + pad read", rc, buttons, 0);
    if (R_SUCCEEDED(rc)) {
        out("  buttons held right now: 0x%08llX", (unsigned long long)buttons);
        out("  (hold a button while the probe runs to see it here)");
    } else {
        out("  a sysmodule cannot read the controller on this setup");
        out("  -> the hotkey feature needs another route (see docs/HOTKEY.md)");
    }
}

/* Wait until a game (a cheat process) exists: this sysmodule is loaded by boot2,
   where no title is running yet.  Without this the whole debug section silently
   reports nothing. */
static bool waitForTarget(u32 timeout_ms) {
    u64 start = armTicksToNs(armGetSystemTick()) / 1000000ull;
    u32 last_note = 0;
    u32 last_open = 0xFFFFFFFFu;
    for (;;) {
        bool has = false;
        if (R_SUCCEEDED(nxusDmntHasCheatProcess(&has)) && has) {
            return true;
        }
        /* A running title is visible through pm:dmnt even before its cheat process
           exists, so this is the reliable "a game is up" signal. */
        u64 app_pid = 0;
        if (R_SUCCEEDED(pmdmntGetApplicationProcessId(&app_pid)) && app_pid != 0) {
            out("  foreground application pid=0x%llX", (unsigned long long)app_pid);
            return true;
        }
        /* Titles that are not auto-attached never report a cheat process, so ask
           dmnt to open one for the foreground application.  This has to be retried
           while we wait: at t=0 there is no game yet, and the user may start one
           15 seconds later.  probeDebugSession() closes it again. */
        u64 seconds = (armTicksToNs(armGetSystemTick()) / 1000000ull - start) / 1000ull;
        if ((u32)seconds != last_open && (seconds % 5) == 0) {
            last_open = (u32)seconds;
            Result orc = nxusDmntForceOpen();
            if (R_SUCCEEDED(orc)) {
                out("  opened the cheat process (ForceOpenCheatProcess) at %llu s",
                    (unsigned long long)seconds);
            }
        }
        u64 elapsed = armTicksToNs(armGetSystemTick()) / 1000000ull - start;
        if (elapsed >= timeout_ms) return false;
        if (elapsed / 10000 != last_note) {          /* every ~10 s */
            last_note = (u32)(elapsed / 10000);
            out("  waiting for a running game... (%llu s)", (unsigned long long)(elapsed / 1000));
        }
        svcSleepThread(500000000ull);                /* 500 ms */
    }
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;

    /* The whole point of the probe is this file, so make several attempts at a path
       that works: sdmc:/nxus may be unwritable (or the card read-only), and a silently
       missing report would look like "the probe did nothing". */
    mkdir("sdmc:/nxus", 0777);
    static const char *const log_paths[] = {
        "sdmc:/nxus/probe.txt",
        "sdmc:/probe.txt",
        "sdmc:/switch/probe.txt",     /* always present on an Atmosphère card */
    };
    for (unsigned i = 0; i < sizeof(log_paths) / sizeof(log_paths[0]) && g_Out == NULL; i++) {
        g_Out = fopen(log_paths[i], "wb");
        if (g_Out != NULL && i != 0) {
            out("(report written to %s - the preferred path was not writable)", log_paths[i]);
        }
    }

    /* Written and flushed immediately: if this file is missing after a reboot the
       sysmodule simply did not run (boot2 not honoured / not the emuMMC that has it),
       which is otherwise indistinguishable from "it ran but produced no output". */
    {
        static const char *const markers[] = { "sdmc:/nxus/probe_started.txt",
                                               "sdmc:/probe_started.txt" };
        for (unsigned i = 0; i < sizeof(markers) / sizeof(markers[0]); i++) {
            FILE *m = fopen(markers[i], "wb");
            if (m == NULL) continue;
            u32 v = hosversionGet();
            fprintf(m, "probe sysmodule started\nbuild: %s %s\nfirmware: %u.%u.%u\n",
                    __DATE__, __TIME__, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF);
            fclose(m);
            break;
        }
    }

    out("================================================================");
    out(" Nxus hardware probe");
    {
        u32 v = hosversionGet();
        out(" firmware : %u.%u.%u (hosversion 0x%08X)", (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF, v);
    }
    out(" (build id of this probe: %s %s)", __DATE__, __TIME__);
    out("================================================================");

    out("");
    out("--- waiting for a target ---------------------------------------");
    if (waitForTarget(120000u)) {
        out("  target found");
    } else {
        out("  NO GAME after 120 s: start one and reload the probe.  Everything below");
        out("  that needs a target is reported as 'untested', not as a failure.");
    }

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
    out("--- done.  copy sdmc:/nxus/probe.txt back to the PC -------------");

    if (g_Out != NULL) fclose(g_Out);
    g_Out = NULL;

    while (true) {
        svcSleepThread(1000000000ull);
    }
    return 0;
}
