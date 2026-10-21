#include "nxus_debug.h"

#include "nxus_dmntcht.h"
#include "nxus_log.h"
#include "nxus_net.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#define NXUS_DEBUG_MAX_BREAKS  8
#define NXUS_DEBUG_MAX_HITS    32
#define NXUS_DEBUG_MAX_THREADS 32

typedef struct {
    u32 slot;
    u32 kind;
    u32 size;
    u32 enabled;
    u64 address;
    u64 ctrl;
} BreakSlot;

static Handle g_Debug = INVALID_HANDLE;
static bool   g_Attached = false;
static Thread g_EventThread;
static bool   g_EventThreadLive = false;
static atomic_bool g_StopLoop;

static BreakSlot g_Breaks[NXUS_DEBUG_MAX_BREAKS];
static u32       g_BreakCount;

static NxusBreakHit g_Hits[NXUS_DEBUG_MAX_HITS];
static u32          g_HitCount;      /* entries currently stored */
static u32          g_HitTotal;      /* ever recorded (also the next index) */
static u32          g_HitNext;       /* ring position */

static NxusThreadEntry g_Threads[NXUS_DEBUG_MAX_THREADS];
static u32             g_ThreadCount;

static NxusDebugConfig g_Config;
static s32             g_LastResult;
static Mutex           g_Mutex;

/* Whether the debugged process was created as AArch64.  A 32-bit process keeps
   SP/LR/FP in r13/r14/r11, and libnx does not copy them into the header fields. */
static bool            g_Is64Bit = false;

/* ---- control word construction ----------------------------------------- */

/* Slots 0-5 exist; 0-3 are the watchpoints (addressed as 0x10+n) and 4/5 are the
   two slots a watchpoint may link to.  Arm and detach must agree on this. */
static u32 styleLinkSlot(u32 style) {
    return (style == NXUS_WATCH_STYLE_LINK5) ? 5u : 4u;
}

/* The DBGBVR/DBGWVR value a breakpoint must be programmed with: the kernel only
   compares aligned words, so the byte mask (BAS) lives in the ctrl word and the
   value itself has to be rounded down.  Passing an unaligned value makes the BAS
   bits above the low word silently ignored and the breakpoint never fires. */
static u64 hwBreakValue(u32 kind, u64 address) {
    return (kind == NxusBp_Execute) ? (address & ~3ull) : (address & ~7ull);
}

/* ---- per-core hardware breakpoint arming -------------------------------- */

/* svcSetHardwareBreakPoint only programs the DBGB*R of the core the calling
   thread is currently executing on, and Nxus runs on core 3 by default while the
   game runs on cores 0-2.  Every armed slot must therefore be written once per
   core: migrate the calling thread through cores 0-3 and re-issue the call on
   each, then restore its original affinity.  This mirrors Atmosphère's
   dmnt2_hardware_breakpoint.cpp. */
static Result setHardwareBreakPointAllCores(u32 slot, u64 ctrl, u64 value) {
    s32 orig_core = 0;
    u64 orig_mask = 0;
    Result mrc = svcGetThreadCoreMask(&orig_core, &orig_mask, CUR_THREAD_HANDLE);
    Result first_err = 0;
    for (s32 core = 0; core < 4; core++) {
        if (R_SUCCEEDED(mrc)) {
            svcSetThreadCoreMask(CUR_THREAD_HANDLE, core, (1ull << core));
        }
        Result rc = svcSetHardwareBreakPoint(slot, ctrl, value);
        if (R_FAILED(rc) && R_SUCCEEDED(first_err)) {
            first_err = rc;
        }
    }
    if (R_SUCCEEDED(mrc)) {
        svcSetThreadCoreMask(CUR_THREAD_HANDLE, orig_core, orig_mask);
    }
    return first_err;
}

/* A 32-bit process reports zeros in the SP/LR/FP header fields of ThreadContext
   while the live values sit in the general-purpose registers. */
static bool isContextAArch32(const ThreadContext *ctx) {
    return !g_Is64Bit ||
           (ctx->sp == 0 && ctx->lr == 0 &&
            (ctx->cpu_gprs[13].r != 0 || ctx->cpu_gprs[14].r != 0));
}

/* Byte-address-select for a watchpoint: bits 5..8 of DBGWCR select which bytes of
   the 8-byte word are watched, so an unaligned address must SHIFT the mask by
   (address & 7).  The reference implementation does the same
   (noexs, client/src/me/mdbell/noexs/core/Debugger.java:194-195).  A value that
   straddles two words cannot be expressed; the rest of the word is watched. */
static u64 watchBas(u32 size, u64 address) {
    u32 offset = (u32)(address & 7u);
    u32 bits = (size == 8) ? 8u : size;
    if (bits == 0) bits = 1;
    if (offset + bits > 8u) bits = 8u - offset;      /* clamp: watch to the word end */
    u64 bas = (((1ull << bits) - 1ull) << offset) << 5;
    return bas;
}

u64 nxusDebugBuildControl(u32 kind, u32 size, u64 address, u32 style) {
    if (kind == NxusBp_Execute) {
        /* DBGBCR: E | BAS | BT | LBN.  The kernel rejects BT = 0b0000 (unlinked)
           for an instruction breakpoint with ResultInvalidCombination (0xE801), so
           BT must be 0b0001 (linked instruction address match) and LBN must name
           the slot that holds the context-id breakpoint - the same shape
           Atmosphère's dmnt2 clients use.  BAS selects the instruction bytes, so a
           2-byte breakpoint at base+2 watches bytes 2..3, not 0..1. */
        u64 bas = (size == 2) ? (((address & 2u) ? 0xCull : 0x3ull) << 5)
                              : (0xFull << 5);
        u64 lbn = (u64)styleLinkSlot(style) << 16;
        return (0x1ull << 20) | lbn | bas | 0x1ull;
    }

    /* DBGWCR: E | LSC | BAS | LINK(linked breakpoint number, bits 19:16) */
    u64 lsc;
    switch (kind) {
        case NxusBp_Read:   lsc = 0x01ull << 3; break;
        case NxusBp_Access: lsc = 0x03ull << 3; break;
        case NxusBp_Write:
        default:            lsc = 0x02ull << 3; break;
    }

    /* BAS from the address, not from the size alone: a watch on base+2 must select
       bytes 2..5 of the word, not 0..3. */
    u64 bas = watchBas(size, address);

    /* LBN must name the slot holding the linked context breakpoint: only 4 and 5 are
       free (0-3 are the watchpoints themselves, which is why watchpoint slots are
       addressed as 0x10 + n). */
    u64 link = 0;
    if (style == NXUS_WATCH_STYLE_LINK5) link = 5ull << 16;
    else if (style == NXUS_WATCH_STYLE_LINK6) link = 4ull << 16;

    return 0x1ull | lsc | bas | link;
}

u32 nxusDebugSlotForKind(u32 kind, u32 index) {
    if (kind == NxusBp_Execute) return index % 6;          /* 0..5 */
    return 0x10 + (index % 4);                             /* 0x10..0x13 */
}

/* ---- state helpers ----------------------------------------------------- */

static BreakSlot *findBreakBySlot(u32 slot) {
    for (u32 i = 0; i < g_BreakCount; i++) {
        if (g_Breaks[i].slot == slot) return &g_Breaks[i];
    }
    return NULL;
}

static u32 allocSlot(u32 kind) {
    u32 base = (kind == NxusBp_Execute) ? 0 : 0x10;
    u32 limit = (kind == NxusBp_Execute) ? 6 : 4;
    /* The context-id breakpoint always owns the style's link slot (armContextIdBreakpoint()
       arms it for every style, because an execution breakpoint cannot be armed without
       it); handing that slot to an execution breakpoint would silently kill every
       linked watchpoint. */
    const u32 link = styleLinkSlot(g_Config.style);
    for (u32 i = 0; i < limit; i++) {
        if (base + i == link) continue;
        if (findBreakBySlot(base + i) == NULL) return base + i;
    }
    return 0xFFFFFFFFu;
}

static void armContextIdBreakpoint(void) {
    const u32 slot = styleLinkSlot(g_Config.style);
    /* BT = 0b0011 = LINKED_CONTEXT_IDR_MATCH: the type the working reference
       implementation arms for its link source (jnoexs/noexs,
       client/src/me/mdbell/noexs/misc/BreakpointType.java), with the debug handle as
       the value.  Our previous 0b0100 means "unlinked instruction address mismatch". */
    const u64 ctrl = (0x3ull << 20) | 0x1E1ull;
    /* The value of a context-id breakpoint is the debug handle: the kernel turns
       it into the process id.  Passing 0 arms nothing, which silently disables
       every LINK5/LINK6 watchpoint - and every execution breakpoint links here. */
    Result rc = setHardwareBreakPointAllCores(slot, ctrl, (u64)g_Debug);
    NXUS_LOG("ctx-id breakpoint slot %u rc=0x%08X", (unsigned)slot, (unsigned)rc);
}

/* ---- hit recording ----------------------------------------------------- */

/* Upper bound on async hit events pushed to the PC per second; the rest are
   available through the hit ring. */
#define NXUS_DEBUG_EVENTS_PER_SECOND 20u

static void recordHit(const DebugEventInfo *event) {
    NxusBreakHit hit;
    memset(&hit, 0, sizeof(hit));

    const u32 bp_type = event->info.exception.specific.break_point.type;
    /* On hardware the kernel frequently reports 0 in break_point.address for a
       watchpoint exception (observed: "last watch addr=00000000 pc=21122038"), so
       the raw field is useless for matching.  Fall back to the exception address
       first and to the armed slot's address afterwards. */
    u64 raw_addr = (u64)event->info.exception.specific.break_point.address;
    if (raw_addr == 0) raw_addr = (u64)event->info.exception.address;

    hit.address = raw_addr;
    hit.kind = (bp_type == BreakPointType_HardwareData) ? NxusBp_Write : NxusBp_Execute;
    hit.thread_id_low = (u32)event->thread_id;
    hit.slot = 0xFFFFFFFFu;

    /* The exception reports the value the breakpoint was programmed with, which is
       the aligned address, not necessarily the address the user asked for.  Match
       either form and report the user's address so the PC can identify the hit.
       Skipped when the kernel gave us nothing: comparing 0 would match any
       breakpoint armed in the lowest 8-byte word. */
    if (raw_addr != 0) {
        for (u32 i = 0; i < g_BreakCount; i++) {
            if (!g_Breaks[i].enabled) continue;
            const bool exact = (g_Breaks[i].address == hit.address);
            const bool same_word = (g_Breaks[i].kind == NxusBp_Execute)
                                       ? ((g_Breaks[i].address & ~3ull) == (hit.address & ~3ull))
                                       : ((g_Breaks[i].address & ~7ull) == (hit.address & ~7ull));
            if (exact || same_word) {
                hit.slot = g_Breaks[i].slot;
                hit.kind = g_Breaks[i].kind;
                if (hit.kind != NxusBp_Execute) hit.address = g_Breaks[i].address;
                break;
            }
        }
    }

    /* No usable address from the kernel: attribute the hit to the armed slot whose
       type matches the exception (a data watchpoint exception can only come from a
       watch slot, an instruction breakpoint only from an execution slot).  Without
       this the PC sees slot=0xFFFFFFFF/addr=0 and cannot map the hit at all. */
    if (hit.slot == 0xFFFFFFFFu) {
        const bool want_exec = (bp_type != BreakPointType_HardwareData);
        for (u32 i = 0; i < g_BreakCount; i++) {
            if (!g_Breaks[i].enabled) continue;
            const bool is_exec = (g_Breaks[i].kind == NxusBp_Execute);
            if (is_exec != want_exec) continue;
            hit.slot = g_Breaks[i].slot;
            hit.kind = g_Breaks[i].kind;
            if (hit.address == 0) hit.address = g_Breaks[i].address;
            break;
        }
    }

    ThreadContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    if (R_SUCCEEDED(svcGetDebugThreadContext(&ctx, g_Debug, event->thread_id, RegisterGroup_CpuAll))) {
        hit.pc = ctx.pc.x;
        hit.cpsr = ctx.psr;
        for (u32 i = 0; i < 13; i++) hit.r[i] = ctx.cpu_gprs[i].r;
        if (isContextAArch32(&ctx)) {
            hit.sp = ctx.cpu_gprs[13].r;
            hit.lr = ctx.cpu_gprs[14].r;
        } else {
            hit.lr = ctx.lr;
            hit.sp = ctx.sp;
        }
    }

    mutexLock(&g_Mutex);
    hit.index = g_HitTotal++;
    hit.tick = armGetSystemTick();
    g_Hits[g_HitNext] = hit;
    g_HitNext = (g_HitNext + 1) % NXUS_DEBUG_MAX_HITS;
    if (g_HitCount < NXUS_DEBUG_MAX_HITS) g_HitCount++;
    mutexUnlock(&g_Mutex);

    /* A hot watchpoint fires hundreds of times per second.  One SD-card append
       per hit (fopen/fwrite/fclose) plus one socket send under the shared mutex
       would keep the target stopped for the whole burst, so:
         - the log gets an aggregate line about once per second,
         - the ring above always holds the full history (the client polls it),
         - the async event stream is rate limited. */
    static u32 log_hits = 0;
    static u64 log_window = 0;
    static u32 event_count = 0;
    static u64 event_window = 0;
    const u64 now = armGetSystemTick();

    log_hits++;
    if (log_window == 0 || armTicksToNs(now - log_window) > 1000000000ull) {
        NXUS_LOG("debug: %u hit(s) in the last second (last %s addr=%08llX pc=%08llX)",
                 (unsigned)log_hits, (hit.kind == NxusBp_Execute) ? "exec" : "watch",
                 (unsigned long long)hit.address, (unsigned long long)hit.pc);
        log_window = now;
        log_hits = 0;
    }

    if (event_window == 0 || armTicksToNs(now - event_window) > 1000000000ull) {
        event_window = now;
        event_count = 0;
    }
    if (event_count < NXUS_DEBUG_EVENTS_PER_SECOND) {
        event_count++;
        nxusNetSendEvent(NxusEvent_BreakHit, &hit, (u32)sizeof(hit));
    }
}

/* ---- debug event loop -------------------------------------------------- */

static void noteThread(u64 thread_id) {
    if (thread_id == 0) return;
    mutexLock(&g_Mutex);
    for (u32 i = 0; i < g_ThreadCount; i++) {
        if (g_Threads[i].thread_id == thread_id) { mutexUnlock(&g_Mutex); return; }
    }
    if (g_ThreadCount < NXUS_DEBUG_MAX_THREADS) {
        memset(&g_Threads[g_ThreadCount], 0, sizeof(g_Threads[0]));
        g_Threads[g_ThreadCount].thread_id = thread_id;
        g_ThreadCount++;
    }
    mutexUnlock(&g_Mutex);
}

/* ---- temporary disarm / re-arm around a continue ----------------------- */

/* A hardware breakpoint that is still armed when the target resumes traps on the
   very same instruction again (the PC never advanced past it), and continuing from
   the event handler therefore freezes the title in an endless trap loop.  Disarm
   every armed slot on every core, let the instruction retire, then re-apply what
   is still enabled.  The context-id breakpoint is part of the set: it is armed for
   every style now, and clearing it would break the link of every execution
   breakpoint. */
static void disarmAllBreaks(void) {
    mutexLock(&g_Mutex);
    for (u32 i = 0; i < g_BreakCount; i++) {
        if (g_Breaks[i].enabled) {
            setHardwareBreakPointAllCores(g_Breaks[i].slot, 0, 0);
        }
    }
    setHardwareBreakPointAllCores(styleLinkSlot(g_Config.style), 0, 0);
    mutexUnlock(&g_Mutex);
}

static void rearmAllBreaks(void) {
    mutexLock(&g_Mutex);
    const u64 ctx_ctrl = (0x3ull << 20) | 0x1E1ull;
    setHardwareBreakPointAllCores(styleLinkSlot(g_Config.style), ctx_ctrl, (u64)g_Debug);
    for (u32 i = 0; i < g_BreakCount; i++) {
        if (g_Breaks[i].enabled) {
            setHardwareBreakPointAllCores(g_Breaks[i].slot, g_Breaks[i].ctrl,
                                          hwBreakValue(g_Breaks[i].kind, g_Breaks[i].address));
        }
    }
    mutexUnlock(&g_Mutex);
}

static void eventThread(void *arg) {
    (void)arg;
    while (!atomic_load_explicit(&g_StopLoop, memory_order_relaxed)) {
        if (!g_Attached) break;

        DebugEventInfo event;
        memset(&event, 0, sizeof(event));
        Result rc = svcGetDebugEvent(&event, g_Debug);
        if (R_FAILED(rc)) {
            /* no event pending (or the session ended): yield and retry */
            svcSleepThread(2000000ull);
            continue;
        }

        bool is_break = false;
        switch (event.type) {
            case DebugEventType_CreateProcess:
                /* The flags bit 0 tells whether the process is AArch64; the
                   32-bit view keeps SP/LR/FP in r13/r14/r11. */
                g_Is64Bit = (event.info.create_process.flags & 1u) != 0;
                NXUS_LOG("debug: process created (pid=%llu, %s)",
                         (unsigned long long)event.info.create_process.process_id,
                         g_Is64Bit ? "AArch64" : "AArch32");
                break;
            case DebugEventType_CreateThread:
                noteThread(event.thread_id);
                break;
            case DebugEventType_Exception:
                if (event.info.exception.type == DebugException_BreakPoint) {
                    recordHit(&event);
                    is_break = true;
                } else {
                    NXUS_LOG("debug: exception type %u at %p",
                             (unsigned)event.info.exception.type, event.info.exception.address);
                }
                break;
            case DebugEventType_ExitProcess:
                NXUS_LOG("debug: process exited");
                break;
            default:
                break;
        }

        /* With auto_continue == 0 a breakpoint hit is meant to HOLD the target
           (that is what a debugger stop is for), so it must not be resumed until
           the PC asks for it.  Everything else - the initial CreateProcess /
           CreateThread burst in particular - is always continued, otherwise attach
           itself would freeze the title. */
        if (is_break && g_Config.auto_continue == 0) {
            NXUS_LOG("debug: breakpoint hit while auto_continue=0, target held");
            continue;
        }

        /* 4|2|1 = ContinueAll | ContinueOthers | IgnoreException: the form the
           working reference implementation uses on hardware (noexs,
           server/source/noexs/source/debug.cpp:74).  flags = 0 with a tid list is
           not proven to resume anything, and a stopped target looks like a frozen
           game. */
        u64 tid = event.thread_id;
        if (is_break) {
            /* Step past the trapping instruction: disarm, continue, give the core
               1 ms to retire it, then re-arm what the PC still has enabled. */
            disarmAllBreaks();
            Result crc = svcContinueDebugEvent(g_Debug, 4u | 2u | 1u, &tid, 1);
            if (R_FAILED(crc)) NXUS_RESULT("ContinueDebugEvent", crc);
            svcSleepThread(1000000ull);
            rearmAllBreaks();
        } else {
            Result crc = svcContinueDebugEvent(g_Debug, 4u | 2u | 1u, &tid, 1);
            if (R_FAILED(crc)) NXUS_RESULT("ContinueDebugEvent", crc);
        }
    }
    g_EventThreadLive = false;
}

/* ---- public API -------------------------------------------------------- */

void nxusDebugInit(void) {
    mutexInit(&g_Mutex);
    memset(g_Breaks, 0, sizeof(g_Breaks));
    memset(g_Hits, 0, sizeof(g_Hits));
    memset(g_Threads, 0, sizeof(g_Threads));
    g_Config.style = NXUS_WATCH_STYLE_DEFAULT;
    g_Config.auto_continue = 1;
    g_Is64Bit = false;
    g_Attached = false;
    g_Debug = INVALID_HANDLE;
    atomic_init(&g_StopLoop, true);
}

void nxusDebugExit(void) {
    nxusDebugDetach();
}

bool nxusDebugIsAttached(void) { return g_Attached; }

Result nxusDebugAttach(u64 pid) {
    if (g_Attached) return 0;
    if (pid == 0) return (Result)NXUS_MAKE_RESULT(NXUS_ERR_NO_PROCESS);

    /* Only one debugger may own the process: ask dmnt to detach first. */
    Result rc = nxusDmntForceClose();
    NXUS_RESULT("dmnt ForceCloseCheatProcess", rc);
    svcSleepThread(200000000ull);

    Handle debug = INVALID_HANDLE;
    rc = svcDebugActiveProcess(&debug, pid);
    g_LastResult = (s32)rc;
    NXUS_RESULT("svcDebugActiveProcess", rc);
    if (R_FAILED(rc)) {
        nxusDmntForceOpen();
        return rc;
    }

    g_Debug = debug;
    g_Attached = true;
    g_BreakCount = 0;
    g_ThreadCount = 0;
    atomic_store_explicit(&g_StopLoop, false, memory_order_relaxed);

    armContextIdBreakpoint();

    alignas(0x1000) static u8 eventStack[0x8000];
    rc = threadCreate(&g_EventThread, eventThread, NULL, eventStack, sizeof(eventStack), 0x2A, -2);
    if (R_FAILED(rc)) {
        svcCloseHandle(g_Debug);
        g_Debug = INVALID_HANDLE;
        g_Attached = false;
        nxusDmntForceOpen();
        return rc;
    }
    g_EventThreadLive = true;
    threadStart(&g_EventThread);
    NXUS_LOG("debug mode active (pid=%llu, watch style=%u)", (unsigned long long)pid,
             (unsigned)g_Config.style);
    return 0;
}

Result nxusDebugDetach(void) {
    if (!g_Attached) return 0;

    atomic_store_explicit(&g_StopLoop, true, memory_order_relaxed);

    for (u32 i = 0; i < g_BreakCount; i++) {
        if (g_Breaks[i].enabled) setHardwareBreakPointAllCores(g_Breaks[i].slot, 0, 0);
    }
    /* Unconditional: armContextIdBreakpoint() arms the link slot for every style
       (an execution breakpoint cannot be armed without it), so a stale context
       breakpoint would otherwise stay armed for the rest of the session. */
    setHardwareBreakPointAllCores(styleLinkSlot(g_Config.style), 0, 0);

    if (g_Debug != INVALID_HANDLE) {
        svcCloseHandle(g_Debug);   /* detaches and resumes the target */
        g_Debug = INVALID_HANDLE;
    }
    g_Attached = false;

    if (g_EventThreadLive) {
        threadWaitForExit(&g_EventThread);
        threadClose(&g_EventThread);
        g_EventThreadLive = false;
    }

    svcSleepThread(100000000ull);
    Result rc = nxusDmntForceOpen();
    NXUS_RESULT("dmnt ForceOpenCheatProcess (restore)", rc);
    NXUS_LOG("debug mode released");
    return 0;
}

void nxusDebugGetStatus(NxusDebugStatus *out) {
    if (out == NULL) return;
    memset(out, 0, sizeof(*out));
    out->attached = g_Attached ? 1 : 0;
    out->watch_style = g_Config.style;
    out->break_count = g_BreakCount;
    out->thread_count = g_ThreadCount;
    out->auto_continue = g_Config.auto_continue;
    out->last_result = g_LastResult;
    mutexLock(&g_Mutex);
    out->hit_count = g_HitTotal;
    mutexUnlock(&g_Mutex);
}

Result nxusDebugSetBreak(const NxusBreakRequest *request) {
    if (request == NULL) return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE);
    if (!g_Attached) return (Result)NXUS_MAKE_RESULT(NXUS_ERR_NOT_ATTACHED);

    u32 slot = request->slot;
    if (request->kind == NxusBp_Execute) {
        /* 4/5 hold the context-id link source: an execution breakpoint placed there
           silently disables every linked watchpoint (and now every execution
           breakpoint links to it). */
        const u32 link = styleLinkSlot(g_Config.style);
        if (slot >= 6 || slot == link) slot = allocSlot(NxusBp_Execute);
    } else {
        if (slot < 0x10 || slot > 0x13) slot = allocSlot(request->kind);
    }
    if (slot == 0xFFFFFFFFu) return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BUSY);

    u64 ctrl = request->ctrl ? request->ctrl
                             : nxusDebugBuildControl(request->kind, request->size ? request->size : 4,
                                                     request->address, g_Config.style);
    /* DBGWVR/DBGBVR must hold the aligned word: the byte mask lives in BAS.
       An unaligned value loses the high BAS bits and never fires.  The original
       address is kept in BreakSlot so hits can be reported in user terms. */
    u64 hw_addr = hwBreakValue(request->kind, request->address);
    Result rc = setHardwareBreakPointAllCores(slot, ctrl, hw_addr);
    g_LastResult = (s32)rc;
    NXUS_LOG("set break slot=%u kind=%u addr=%08llX hw=%08llX ctrl=%08llX rc=0x%08X",
             (unsigned)slot, (unsigned)request->kind, (unsigned long long)request->address,
             (unsigned long long)hw_addr, (unsigned long long)ctrl, (unsigned)rc);
    if (R_FAILED(rc)) return rc;

    mutexLock(&g_Mutex);
    BreakSlot *existing = findBreakBySlot(slot);
    if (existing == NULL && g_BreakCount < NXUS_DEBUG_MAX_BREAKS) {
        existing = &g_Breaks[g_BreakCount++];
    }
    if (existing != NULL) {
        existing->slot = slot;
        existing->kind = request->kind;
        existing->size = request->size ? request->size : 4;
        existing->enabled = 1;
        existing->address = request->address;
        existing->ctrl = ctrl;
    }
    mutexUnlock(&g_Mutex);
    return 0;
}

Result nxusDebugClearBreak(u32 slot) {
    if (!g_Attached) return (Result)NXUS_MAKE_RESULT(NXUS_ERR_NOT_ATTACHED);

    Result rc = setHardwareBreakPointAllCores(slot, 0, 0);
    g_LastResult = (s32)rc;

    mutexLock(&g_Mutex);
    for (u32 i = 0; i < g_BreakCount; i++) {
        if (g_Breaks[i].slot == slot) {
            g_Breaks[i] = g_Breaks[g_BreakCount - 1];
            g_BreakCount--;
            break;
        }
    }
    mutexUnlock(&g_Mutex);
    return rc;
}

u32 nxusDebugGetBreaks(NxusBreakEntry *out, u32 max_entries) {
    if (out == NULL) return 0;
    u32 n = 0;
    mutexLock(&g_Mutex);
    for (u32 i = 0; i < g_BreakCount && n < max_entries; i++) {
        out[n].slot = g_Breaks[i].slot;
        out[n].kind = g_Breaks[i].kind;
        out[n].size = g_Breaks[i].size;
        out[n].enabled = g_Breaks[i].enabled;
        out[n].address = g_Breaks[i].address;
        out[n].ctrl = g_Breaks[i].ctrl;
        n++;
    }
    mutexUnlock(&g_Mutex);
    return n;
}

u32 nxusDebugHitTotal(void) {
    mutexLock(&g_Mutex);
    u32 total = g_HitTotal;
    mutexUnlock(&g_Mutex);
    return total;
}

u32 nxusDebugGetHits(NxusBreakHit *out, u32 max_entries) {
    if (out == NULL) return 0;
    mutexLock(&g_Mutex);
    u32 n = (g_HitCount < max_entries) ? g_HitCount : max_entries;
    /* newest first: walk backwards from the ring head */
    for (u32 i = 0; i < n; i++) {
        u32 index = (g_HitNext + NXUS_DEBUG_MAX_HITS - 1 - i) % NXUS_DEBUG_MAX_HITS;
        out[i] = g_Hits[index];
    }
    mutexUnlock(&g_Mutex);
    return n;
}

void nxusDebugClearHits(void) {
    mutexLock(&g_Mutex);
    g_HitCount = 0;
    g_HitNext = 0;
    g_HitTotal = 0;
    memset(g_Hits, 0, sizeof(g_Hits));
    mutexUnlock(&g_Mutex);
}

u32 nxusDebugGetThreads(NxusThreadEntry *out, u32 max_entries) {
    if (out == NULL) return 0;
    if (!g_Attached) {
        mutexLock(&g_Mutex);
        u32 n = (g_ThreadCount < max_entries) ? g_ThreadCount : max_entries;
        for (u32 i = 0; i < n; i++) out[i] = g_Threads[i];
        mutexUnlock(&g_Mutex);
        return n;
    }

    u64 ids[NXUS_DEBUG_MAX_THREADS];
    s32 num = 0;
    if (R_FAILED(svcGetThreadList(&num, ids, NXUS_DEBUG_MAX_THREADS, g_Debug))) return 0;
    u32 n = ((u32)num < max_entries) ? (u32)num : max_entries;
    for (u32 i = 0; i < n; i++) {
        memset(&out[i], 0, sizeof(out[i]));
        out[i].thread_id = ids[i];
    }
    return n;
}

Result nxusDebugGetRegs(u64 thread_id, NxusThreadContext *out) {
    if (out == NULL) return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE);
    if (!g_Attached) return (Result)NXUS_MAKE_RESULT(NXUS_ERR_NOT_ATTACHED);

    ThreadContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    Result rc = svcGetDebugThreadContext(&ctx, g_Debug, thread_id, RegisterGroup_CpuAll);
    if (R_FAILED(rc)) return rc;

    memset(out, 0, sizeof(*out));
    out->thread_id = thread_id;
    out->pc = ctx.pc.x;
    out->cpsr = ctx.psr;
    for (u32 i = 0; i < 13; i++) out->r[i] = ctx.cpu_gprs[i].r;
    for (u32 i = 0; i < 29; i++) out->x[i] = ctx.cpu_gprs[i].x;
    if (isContextAArch32(&ctx)) {
        /* 32-bit titles report 0 in the header fields; the live values are r13/r14
           and the frame pointer is r11.  Mirror the register file into x[] too, so a
           client that only reads x[] still sees the real values. */
        out->sp = ctx.cpu_gprs[13].r;
        out->lr = ctx.cpu_gprs[14].r;
        out->fp = ctx.cpu_gprs[11].r;
        for (u32 i = 0; i < 15; i++) out->x[i] = ctx.cpu_gprs[i].r;
    } else {
        out->lr = ctx.lr;
        out->sp = ctx.sp;
        out->fp = ctx.fp;
    }
    return 0;
}

Result nxusDebugSetRegs(u64 thread_id, const NxusThreadContext *in) {
    if (in == NULL) return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE);
    if (!g_Attached) return (Result)NXUS_MAKE_RESULT(NXUS_ERR_NOT_ATTACHED);

    ThreadContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    /* Read-modify-write so the FPU half of the context stays untouched.  If the
       read fails we must NOT continue: writing an all-zero context would destroy
       the thread's registers (including the SIMD half) and crash the game. */
    Result rc = svcGetDebugThreadContext(&ctx, g_Debug, thread_id, RegisterGroup_CpuAll);
    if (R_FAILED(rc)) return rc;
    ctx.pc.x = in->pc;
    ctx.lr = in->lr;
    ctx.sp = in->sp;
    ctx.fp = in->fp;
    ctx.psr = in->cpsr;
    if (in->reserved & 1u) {
        for (u32 i = 0; i < 29; i++) ctx.cpu_gprs[i].x = in->x[i];
    } else {
        for (u32 i = 0; i < 13; i++) {
            ctx.cpu_gprs[i].x = (in->x[i] != 0) ? in->x[i] : (u64)in->r[i];
        }
        for (u32 i = 13; i < 29; i++) {
            if (in->x[i] != 0) ctx.cpu_gprs[i].x = in->x[i];
        }
    }
    if (isContextAArch32(&ctx)) {
        /* 32-bit: the header fields above are not what the core restores, so the
           values the user typed must go into the real registers.  Done after the
           generic block on purpose: that block writes r11 via x[11]/r[11]. */
        ctx.cpu_gprs[11].x = (u32)in->fp;
        ctx.cpu_gprs[13].x = (u32)in->sp;
        ctx.cpu_gprs[14].x = (u32)in->lr;
    }
    return svcSetDebugThreadContext(g_Debug, thread_id, &ctx, RegisterGroup_CpuAll);
}

Result nxusDebugContinueAll(void) {
    if (!g_Attached) return (Result)NXUS_MAKE_RESULT(NXUS_ERR_NOT_ATTACHED);

    u64 ids[NXUS_DEBUG_MAX_THREADS];
    s32 num = 0;
    if (R_FAILED(svcGetThreadList(&num, ids, NXUS_DEBUG_MAX_THREADS, g_Debug)) || num <= 0) {
        return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE);
    }
    /* Same flags as the per-event path above, and the same step discipline: an armed
       breakpoint would trap on the instruction it already trapped on, so disarm,
       let the core make progress, then re-arm. */
    disarmAllBreaks();
    Result rc = svcContinueDebugEvent(g_Debug, 4u | 2u | 1u, ids, (u32)num);
    if (R_SUCCEEDED(rc)) svcSleepThread(1000000ull);
    rearmAllBreaks();
    g_LastResult = (s32)rc;
    return rc;
}

Result nxusDebugReadMemory(u64 address, void *buffer, u32 size) {
    if (!g_Attached) return (Result)NXUS_MAKE_RESULT(NXUS_ERR_NOT_ATTACHED);
    return svcReadDebugProcessMemory(buffer, g_Debug, address, size);
}

Result nxusDebugWriteMemory(u64 address, const void *buffer, u32 size) {
    if (!g_Attached) return (Result)NXUS_MAKE_RESULT(NXUS_ERR_NOT_ATTACHED);
    return svcWriteDebugProcessMemory(g_Debug, buffer, address, size);
}

Result nxusDebugQueryMemory(u64 address, NxusMemoryInfo *out) {
    if (out == NULL) return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE);
    if (!g_Attached) return (Result)NXUS_MAKE_RESULT(NXUS_ERR_NOT_ATTACHED);

    MemoryInfo info;
    u32 page_info = 0;
    memset(&info, 0, sizeof(info));
    Result rc = svcQueryDebugProcessMemory(&info, &page_info, g_Debug, address);
    if (R_FAILED(rc)) return rc;

    out->base_addr = info.addr;
    out->size = info.size;
    out->memory_type = info.type;
    out->memory_attribute = info.attr;
    out->perm = info.perm;
    out->device_refcount = info.device_refcount;
    out->ipc_refcount = info.ipc_refcount;
    out->padding = 0;
    return 0;
}

void nxusDebugConfigure(const NxusDebugConfig *config) {
    if (config == NULL) return;
    if (config->style <= NXUS_WATCH_STYLE_LINK6) g_Config.style = config->style;
    g_Config.auto_continue = config->auto_continue;
    if (g_Attached) armContextIdBreakpoint();
}

void nxusDebugGetConfig(NxusDebugConfig *out) {
    if (out != NULL) *out = g_Config;
}
