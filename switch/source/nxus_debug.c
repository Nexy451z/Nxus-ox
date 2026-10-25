#include "nxus_debug.h"

#include "nxus_dmntcht.h"
#include "nxus_log.h"
#include "nxus_net.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#define NXUS_DEBUG_MAX_HITS    32
#define NXUS_DEBUG_MAX_THREADS 32

/* The break table size (NXUS_DEBUG_MAX_BREAKS) lives in nxus_debug.h: the server
   sizes its break-list reply from it, and the table must cover all ten hardware
   slots (6 instruction + 4 watch). */

typedef struct {
    u32 slot;
    u32 kind;
    u32 size;
    u32 enabled;
    u64 address;
    u64 ctrl;
    /* Hot-breakpoint burst guard: a breakpoint that fires every frame (or in a
       hot loop) must not keep the target stopped for a whole burst.  Hits are
       counted in a sliding one-second window and the slot is auto-disarmed
       after a small number of hits (see recordHit()). */
    u32 hits_in_window;
    u64 window_start_tick;
} BreakSlot;

static Handle g_Debug = INVALID_HANDLE;
static bool   g_Attached = false;
static Thread g_EventThread;
static bool   g_EventThreadLive = false;
static atomic_bool g_StopLoop;
/* Set when the debugee exits: the session is dead but must be collected from a
   thread that is not the event thread (detach joins it).  nxusServerTick() does
   that and restores dmnt; until then nxusDebugAttach() refuses to start again. */
static atomic_bool g_ExitSeen;
/* svcGetDebugEvent / svcContinueDebugEvent must never be issued by two threads at
   once: the event thread and the command thread (continue / step / break) both
   drain the queue, and an interleaved pair makes the kernel answer Busy or, worse,
   resumes while the other side still believes the target is held.  Recursive so
   continueAllOnce() can call drainDebugEvents() while holding it. */
static RMutex g_EventMutex;
static bool   g_EventMutexReady;
/* True while nxusDebugAttach()/Detach() is handing the process between dmnt and
   our own debug session.  dmnt's auto-reopen must not run in that window (it
   would take the process back and make svcDebugActiveProcess fail), and the
   session identity refresh must not call into dmnt either (it would reopen it). */
static atomic_bool g_HandoffBusy;
/* The scan worker reads/writes through g_Debug while the command thread may be
   detaching.  svcCloseHandle() frees the handle slot, and the kernel reuses it for
   the next object, so a read that started before the close can end up touching an
   unrelated handle.  Detach marks g_DebugClosing and waits for the in-flight count
   to reach zero before it closes. */
static atomic_int  g_DebugOpUsers;
static atomic_bool g_DebugClosing;

static Result debugOpBegin(void) {
    if (atomic_load_explicit(&g_DebugClosing, memory_order_acquire)) {
        return (Result)NXUS_MAKE_RESULT(NXUS_ERR_NOT_ATTACHED);
    }
    atomic_fetch_add_explicit(&g_DebugOpUsers, 1, memory_order_acq_rel);
    if (atomic_load_explicit(&g_DebugClosing, memory_order_acquire) || !g_Attached) {
        atomic_fetch_sub_explicit(&g_DebugOpUsers, 1, memory_order_acq_rel);
        return (Result)NXUS_MAKE_RESULT(NXUS_ERR_NOT_ATTACHED);
    }
    return 0;
}

static void debugOpEnd(void) {
    atomic_fetch_sub_explicit(&g_DebugOpUsers, 1, memory_order_acq_rel);
}

/* Why the current stop exists.  The event loop uses it to tell an explicit
   debugger stop (Pause, Step) apart from a stop left over from auto_continue == 0
   mode: only the former may hold the target while auto-continue is on. */
typedef enum {
    StopReason_Hit    = 0,   /* breakpoint / watchpoint hit (GDB-style hold) */
    StopReason_Manual = 1,   /* svcBreakDebugProcess: an explicit Pause        */
    StopReason_Step   = 2,   /* nxusDebugStep(): an explicit single step        */
} StopReason;

/* GDB-style stop state.  With g_Config.auto_continue == 0 (the default) a
   breakpoint/watchpoint hit must HOLD the target instead of resuming it, so the
   PC can read registers and memory.  g_Stopped says the target is being held and
   g_StoppedThread remembers the thread that took the exception, which is what
   DebugStep and the status reply report.  Both are written from the event thread
   and read from the command thread. */
static atomic_bool   g_Stopped;
static atomic_ullong g_StoppedThread;
static atomic_uint   g_StopReason;
/* Bumped for every published stop.  nxusDebugContinueAll() uses it to tell "the
   stop I am resuming from" apart from "a hit that fired while the slots were
   going back in", which must not be cleared when the continue returns.  Only
   publishStopState() may touch it, so a manual Break or a Step can never leave a
   stale sequence number behind. */
static atomic_uint   g_StopSeq;
/* Bumped for every exception event consumed (by either the event thread or a
   command-thread drain).  nxusDebugStep() uses it to wait - bounded - for the
   exception that stops the target again after it resumed. */
static atomic_uint   g_ExceptionSeq;

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
   SP/LR/FP in r13/r14/r11, and libnx does not copy them into the header fields.
   The event thread writes this when the CreateProcess event arrives while the
   command thread reads it in nxusDebugGetRegs()/SetRegs()/recordHit(): with a
   plain bool a 32-bit title could observe a torn/false value for a moment and
   would then read (or worse, write) the AArch64 header SP/LR, destroying the
   wrong registers.  Release/acquire publishes the flag together with the rest of
   the session state. */
static atomic_bool     g_Is64Bit;

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

/* One register write: slot 0..5 = instruction breakpoint, 0x10..0x13 = watchpoint. */
typedef struct {
    u32 slot;
    u64 ctrl;
    u64 value;
} HwSlotWrite;

/* svcSetHardwareBreakPoint only programs the DBGB*R of the core the calling
   thread is currently executing on, and Nxus runs on core 3 by default while the
   game runs on cores 0-2.  Every armed slot must therefore be written once per
   core: migrate the calling thread through cores 0-3 and re-issue the call on
   each, then restore its original affinity.  This mirrors Atmosphère's
   dmnt2_hardware_breakpoint.cpp.

   The migration itself is the expensive part (it stops the thread and moves it),
   so program a whole *batch* while parked on each core instead of migrating once
   per slot: a detach that wipes ten slots costs 4 migrations instead of 40, and
   the hit path's disarm/re-arm pair drops from ~200 SVCs to ~30. */
static Result programSlotsAllCores(const HwSlotWrite *writes, u32 count) {
    if (count == 0) return 0;

    s32 orig_core = 0;
    u64 orig_mask = 0;
    Result mrc = svcGetThreadCoreMask(&orig_core, &orig_mask, CUR_THREAD_HANDLE);
    Result first_err = 0;

    for (s32 core = 0; core < 4; core++) {
        if (R_SUCCEEDED(mrc)) {
            svcSetThreadCoreMask(CUR_THREAD_HANDLE, core, (1ull << core));
        }
        for (u32 i = 0; i < count; i++) {
            Result rc = svcSetHardwareBreakPoint(writes[i].slot, writes[i].ctrl, writes[i].value);
            if (R_FAILED(rc) && R_SUCCEEDED(first_err)) {
                first_err = rc;
            }
        }
    }
    if (R_SUCCEEDED(mrc)) {
        svcSetThreadCoreMask(CUR_THREAD_HANDLE, orig_core, orig_mask);
    }
    return first_err;
}

static Result setHardwareBreakPointAllCores(u32 slot, u64 ctrl, u64 value) {
    HwSlotWrite write = { slot, ctrl, value };
    return programSlotsAllCores(&write, 1);
}

/* Wipe every hardware breakpoint/watchpoint register on every core.
   Slots 0..5 are the instruction breakpoints (4 and 5 double as the ContextID
   link sources) and 0x10..0x13 are the four watchpoints.  A stale register left
   armed from a previous session fires into whatever process runs next - the
   kernel does not reset the debug breakpoint/watchpoint registers on handle
   close - so both attach and detach clear the entire set, unconditionally. */
static void clearAllHardwareSlots(void) {
    HwSlotWrite writes[10];
    u32 n = 0;
    for (u32 slot = 0; slot <= 5; slot++) writes[n++] = (HwSlotWrite){ slot, 0, 0 };
    for (u32 slot = 0x10; slot <= 0x13; slot++) writes[n++] = (HwSlotWrite){ slot, 0, 0 };
    programSlotsAllCores(writes, n);
}

/* svcContinueDebugEvent returns ResultBusy (0xF401) while even one queued debug
   event is unread, and then it resumes nothing at all.  The value shows up both
   as the bare kernel frame (module 1, description 122) and with the 0xE0000000
   marker, so match either form. */
#define NXUS_DEBUG_RESULT_BUSY_LOW   0x0000F401u
#define NXUS_DEBUG_RESULT_BUSY_FULL  0xE000F401u

static bool isDebugBusyResult(Result rc) {
    const u32 value = (u32)rc;
    return value == NXUS_DEBUG_RESULT_BUSY_LOW || value == NXUS_DEBUG_RESULT_BUSY_FULL;
}

/* A 32-bit process reports zeros in the SP/LR/FP header fields of ThreadContext
   while the live values sit in the general-purpose registers.  The flag is read
   with acquire so a caller that sees the AArch32 state also sees the session
   state published with it. */
static bool isContextAArch32(const ThreadContext *ctx) {
    const bool is64 = atomic_load_explicit(&g_Is64Bit, memory_order_acquire);
    return !is64 ||
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

/* Publish a GDB-style stop.  The kernel has already debug-suspended every thread
   of the process when the exception is queued, so the state below simply records
   that the event loop must NOT acknowledge the event: the target stays frozen and
   the PC can inspect it.

   This is the ONLY place that sets g_Stopped and the only place that increments
   g_StopSeq: a breakpoint hit, a manual Pause (svcBreakDebugProcess) and a single
   step all publish through it, so a stop can never appear without a new sequence
   number (which nxusDebugContinueAll() relies on).  The reason and the thread are
   stored before the flag, and the flag store is a release, so a reader that sees
   g_Stopped == true also sees a consistent thread/reason. */
static void publishStopState(u64 thread_id, StopReason reason) {
    atomic_store_explicit(&g_StoppedThread, thread_id, memory_order_relaxed);
    atomic_store_explicit(&g_StopReason, (unsigned)reason, memory_order_relaxed);
    atomic_fetch_add_explicit(&g_StopSeq, 1, memory_order_relaxed);
    atomic_store_explicit(&g_Stopped, true, memory_order_release);
}

/* Send the stop to the PC and log it (shared by hits and explicit stops). */
static void sendStopEvent(u64 thread_id, u64 pc, u64 address, u32 kind, u32 slot) {
    NxusDebugStop stop;
    memset(&stop, 0, sizeof(stop));
    stop.thread_id = thread_id;
    stop.pc = pc;
    stop.address = address;
    stop.kind = kind;
    stop.slot = slot;

    NXUS_LOG("debug: stopped thread=%016llX pc=%016llX kind=%u slot=%u addr=%016llX "
             "(send DebugContinue/DebugStep to resume)",
             (unsigned long long)stop.thread_id, (unsigned long long)stop.pc,
             (unsigned)stop.kind, (unsigned)stop.slot,
             (unsigned long long)stop.address);
    /* Without a client connected this is a no-op; the hit ring still holds it. */
    nxusNetSendEvent(NxusEvent_DebugStopped, &stop, (u32)sizeof(stop));
}

static void publishStop(const DebugEventInfo *event, const NxusBreakHit *hit) {
    publishStopState(event->thread_id, StopReason_Hit);
    sendStopEvent(event->thread_id, hit->pc, hit->address, hit->kind, hit->slot);
}

/* Only a stop the debugger asked for explicitly may hold the target while
   auto-continue is enabled. */
static bool stopIsExplicit(void) {
    return atomic_load_explicit(&g_StopReason, memory_order_relaxed) != (unsigned)StopReason_Hit;
}

static void clearStopState(void) {
    atomic_store_explicit(&g_Stopped, false, memory_order_release);
    atomic_store_explicit(&g_StoppedThread, 0, memory_order_relaxed);
}

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

    const u64 now = armGetSystemTick();

    /* Burst auto-disarm guard (see the comment above the threshold): an
       execution breakpoint that hits 8 times, or a watchpoint that hits 16
       times, inside one second is attached to a per-frame instruction or a hot
       loop.  Keeping it armed would stop the title on every iteration for the
       whole session; disable it after the burst has been recorded and clear the
       hardware register immediately. */
    bool auto_disarmed = false;
    u32  auto_slot = 0;
    u64  auto_addr = 0;
    u32  auto_hits = 0;

    mutexLock(&g_Mutex);
    hit.index = g_HitTotal++;
    hit.tick = now;
    g_Hits[g_HitNext] = hit;
    g_HitNext = (g_HitNext + 1) % NXUS_DEBUG_MAX_HITS;
    if (g_HitCount < NXUS_DEBUG_MAX_HITS) g_HitCount++;

    if (g_Config.auto_continue != 0 && hit.slot != 0xFFFFFFFFu) {
        BreakSlot *bp = findBreakBySlot(hit.slot);
        if (bp != NULL && bp->enabled) {
            if (bp->window_start_tick == 0 ||
                armTicksToNs(now - bp->window_start_tick) >= 1000000000ull) {
                bp->window_start_tick = now;
                bp->hits_in_window = 0;
            }
            bp->hits_in_window++;
            const u32 limit = (bp->kind == NxusBp_Execute) ? 8u : 16u;
            if (bp->hits_in_window >= limit) {
                auto_disarmed = true;
                auto_slot = bp->slot;
                auto_addr = bp->address;
                auto_hits = bp->hits_in_window;
                bp->enabled = 0;
                bp->hits_in_window = 0;
                setHardwareBreakPointAllCores(bp->slot, 0, 0);
            }
        }
    }
    mutexUnlock(&g_Mutex);

    if (auto_disarmed) {
        NXUS_LOG("debug: auto-disarmed hot break slot=%u after %u hits at %08llX",
                 (unsigned)auto_slot, (unsigned)auto_hits, (unsigned long long)auto_addr);
    }

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

    /* GDB-style default: the hit IS the stop.  Record it as such and let the event
       loop keep the target frozen; in auto-continue mode nothing changes and the
       event loop resumes the title as before.  The burst auto-disarm above stays
       auto-continue-only on purpose: stopping is harmless repetition, disarming a
       breakpoint behind the user's back is not. */
    if (g_Config.auto_continue == 0) {
        publishStop(event, &hit);
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
    HwSlotWrite writes[NXUS_DEBUG_MAX_BREAKS + 1];
    u32 n = 0;
    mutexLock(&g_Mutex);
    for (u32 i = 0; i < g_BreakCount; i++) {
        if (g_Breaks[i].enabled) {
            writes[n++] = (HwSlotWrite){ g_Breaks[i].slot, 0, 0 };
        }
    }
    writes[n++] = (HwSlotWrite){ styleLinkSlot(g_Config.style), 0, 0 };
    /* One core migration for the whole batch (see programSlotsAllCores).  Kept
       under g_Mutex: nxusDebugDetach() sets g_Attached=false and wipes the slots
       under the same lock, so a late write can never land after the wipe. */
    programSlotsAllCores(writes, n);
    mutexUnlock(&g_Mutex);
}

/* Re-arm only while the session is alive.  nxusDebugDetach() stops and joins the
   event thread BEFORE it clears the hardware slots, so this guard makes it
   physically impossible for a late rearm to reprogram a core after the detach
   has wiped the registers. */
static void rearmAllBreaks(void) {
    if (!g_Attached || g_Debug == INVALID_HANDLE ||
        atomic_load_explicit(&g_StopLoop, memory_order_relaxed)) {
        return;
    }
    mutexLock(&g_Mutex);
    if (!g_Attached || g_Debug == INVALID_HANDLE ||
        atomic_load_explicit(&g_StopLoop, memory_order_relaxed)) {
        mutexUnlock(&g_Mutex);
        return;
    }
    HwSlotWrite writes[NXUS_DEBUG_MAX_BREAKS + 1];
    u32 n = 0;
    const u64 ctx_ctrl = (0x3ull << 20) | 0x1E1ull;
    writes[n++] = (HwSlotWrite){ styleLinkSlot(g_Config.style), ctx_ctrl, (u64)g_Debug };
    for (u32 i = 0; i < g_BreakCount; i++) {
        if (g_Breaks[i].enabled) {
            writes[n++] = (HwSlotWrite){
                g_Breaks[i].slot, g_Breaks[i].ctrl,
                hwBreakValue(g_Breaks[i].kind, g_Breaks[i].address) };
        }
    }
    /* Batch: a hot watchpoint hit does disarm+rearm, so this halves the number of
       core migrations on the hottest debugger path.  Under g_Mutex so it cannot
       race the detach wipe. */
    programSlotsAllCores(writes, n);
    mutexUnlock(&g_Mutex);
}

/* True while at least one breakpoint is still armed after a hit.  A hot slot
   that recordHit() auto-disarmed must not be re-armed by the event loop. */
static bool anyBreakEnabled(void) {
    bool any = false;
    mutexLock(&g_Mutex);
    for (u32 i = 0; i < g_BreakCount; i++) {
        if (g_Breaks[i].enabled) { any = true; break; }
    }
    mutexUnlock(&g_Mutex);
    return any;
}

/* One debug event.  Returns true for a breakpoint/watchpoint exception, i.e.
   the events that must be acknowledged before the target can run again. */
static bool handleDebugEvent(const DebugEventInfo *event) {
    bool is_break = false;
    switch (event->type) {
        case DebugEventType_CreateProcess: {
            /* The flags bit 0 tells whether the process is AArch64; the
               32-bit view keeps SP/LR/FP in r13/r14/r11.  Release-published so the
               command thread never observes a half-updated session state. */
            const bool is64 = (event->info.create_process.flags & 1u) != 0;
            atomic_store_explicit(&g_Is64Bit, is64, memory_order_release);
            NXUS_LOG("debug: process created (pid=%llu, %s)",
                     (unsigned long long)event->info.create_process.process_id,
                     is64 ? "AArch64" : "AArch32");
            break;
        }
        case DebugEventType_CreateThread:
            noteThread(event->thread_id);
            break;
        case DebugEventType_Exception:
            /* Every exception is a suspend point: nxusDebugStep() waits on this
               counter to know that the target is stopped again (see
               waitForStopException()). */
            atomic_fetch_add_explicit(&g_ExceptionSeq, 1, memory_order_relaxed);
            if (event->info.exception.type == DebugException_BreakPoint) {
                recordHit(event);
                is_break = true;
            } else {
                NXUS_LOG("debug: exception type %u at %p",
                         (unsigned)event->info.exception.type, event->info.exception.address);
            }
            break;
        case DebugEventType_ExitProcess:
            /* The debugee is gone.  The kill/exit event is the end of the debug
               session, but nxusDebugDetach() cannot run here: it joins this very
               thread (self-deadlock) and closes the handle we are reading events
               from.  So drop the stop/attach state right here, re-enable dmnt's
               self-healing and let nxusServerTick() collect the session (close the
               handle, wipe the slots, ForceOpen dmnt).  Leaving g_Attached true
               with auto-reopen disabled used to zombify the sysmodule until a
               restart. */
            clearStopState();
            atomic_store_explicit(&g_ExitSeen, true, memory_order_relaxed);
            atomic_store_explicit(&g_StopLoop, true, memory_order_relaxed);
            g_Attached = false;
            nxusDmntSetAutoReopen(true);
            NXUS_LOG("debug: process exited (reason=%u) - session released, dmnt reopened "
                     "by the server tick",
                     (unsigned)event->info.exit_process.reason);
            break;
        default:
            break;
    }
    return is_break;
}

/* svcContinueDebugEvent() refuses to resume anything while one debug event is
   still queued (ResultBusy / 0xF401).  The loop below always drains the whole
   queue first for exactly that reason.  A bounded drain is used so a process
   that produces events faster than they are consumed cannot starve anything
   else on this thread forever. */
static u32 drainDebugEventsLocked(bool *had_break) {
    u32 processed = 0;
    for (u32 n = 0; n < 64; n++) {
        DebugEventInfo event;
        memset(&event, 0, sizeof(event));
        if (R_FAILED(svcGetDebugEvent(&event, g_Debug))) break;
        processed++;
        if (handleDebugEvent(&event) && had_break != NULL) *had_break = true;
    }
    return processed;
}

/* Locking wrapper: serialises the debug-event queue against the command thread
   (see g_EventMutex).  Callers keep using the original name. */
static u32 drainDebugEvents(bool *had_break) {
    if (g_EventMutexReady) rmutexLock(&g_EventMutex);
    u32 n = drainDebugEventsLocked(had_break);
    if (g_EventMutexReady) rmutexUnlock(&g_EventMutex);
    return n;
}

static void eventThread(void *arg) {
    (void)arg;
    while (!atomic_load_explicit(&g_StopLoop, memory_order_relaxed)) {
        if (!g_Attached || g_Debug == INVALID_HANDLE) break;

        /* Take EVERY queued event before calling ContinueDebugEvent: one unread
           event is enough for the kernel to return 0xF401 and leave all threads
           stopped.  Processing them all also means no breakpoint hit is lost in
           the CreateProcess/CreateThread burst. */
        bool had_break = false;
        const u32 processed = drainDebugEvents(&had_break);
        if (atomic_load_explicit(&g_ExitSeen, memory_order_relaxed)) {
            /* ExitProcess was among the events above: nothing is left to continue
               and the handle must be closed by a thread that can join this one. */
            NXUS_LOG("debug: event loop stopping after ExitProcess");
            break;
        }
        if (processed == 0) {
            /* no event pending (or the session ended): yield and retry */
            svcSleepThread(2000000ull);
            continue;
        }

        /* Holding policy - auto_continue is evaluated FIRST:
             - auto_continue == 0 (GDB-style, the default): a breakpoint hit is a
               stop the PC is meant to inspect, and once a stop has been published
               every further exception is held too (the single-step exception from
               nxusDebugStep(), the DebuggerBreak from svcBreakDebugProcess()), so
               auto-continuing them cannot silently release the title.
             - auto_continue != 0: a hit was already recorded and must be
               acknowledged, so the target keeps running.  A stop left over from
               the previous stop-on-hit mode is dropped here instead of freezing
               the title for ever; only an explicit stop (manual Pause, Step) is
               honoured.  Everything else - the CreateProcess / CreateThread /
               DebuggerAttached burst in particular - is always continued,
               otherwise attach itself would freeze the title. */
        bool hold = false;
        if (g_Config.auto_continue == 0) {
            hold = nxusDebugIsStopped() || had_break;
        } else if (nxusDebugIsStopped()) {
            if (stopIsExplicit()) {
                hold = true;
            } else {
                clearStopState();
                static u64 stale_log_tick = 0;
                const u64 stale_now = armGetSystemTick();
                if (stale_log_tick == 0 ||
                    armTicksToNs(stale_now - stale_log_tick) > 5000000000ull) {
                    NXUS_LOG("debug: auto_continue=1 - discarded a stale stop");
                    stale_log_tick = stale_now;
                }
            }
        }

        if (hold) {
            /* A hot loop can queue these faster than the PC consumes them; one log
               line per five seconds is enough to see what is going on. */
            static u64 hold_log_tick = 0;
            const u64 hold_now = armGetSystemTick();
            if (hold_log_tick == 0 || armTicksToNs(hold_now - hold_log_tick) > 5000000000ull) {
                NXUS_LOG("debug: %s while stopped - target held",
                         had_break ? "breakpoint hit" : "exception");
                hold_log_tick = hold_now;
            }
            continue;
        }

        /* 4|2|1 = ContinueAll | ContinueOthers | IgnoreException, with no tid
           list: the form the working reference implementation uses on hardware
           (noexs, server/source/noexs/source/debug.cpp:74).  When it still
           reports ResultBusy, extra events arrived between the drain and the
           call; drain again and retry instead of leaving the title stopped. */
        if (had_break) {
            disarmAllBreaks();
        }

        Result crc = 0;
        bool continued = false;
        for (int retry = 0; retry < 8; retry++) {
            crc = svcContinueDebugEvent(g_Debug, 4u | 2u | 1u, NULL, 0);
            if (R_SUCCEEDED(crc)) {
                continued = true;
                break;
            }
            if (!isDebugBusyResult(crc)) break;

            bool extra_break = false;
            if (drainDebugEvents(&extra_break) == 0) {
                svcSleepThread(1000000ull);
            }
            had_break = had_break || extra_break;
        }
        if (!continued && R_FAILED(crc)) NXUS_RESULT("ContinueDebugEvent", crc);

        /* Step past the trapping instruction: give the core 1 ms to retire it,
           then re-arm what the PC still has enabled.  Skipped when the hit was a
           hot slot that recordHit() auto-disarmed (nothing left to re-arm) and
           whenever a detach has already started. */
        if (had_break && g_Attached && !atomic_load_explicit(&g_StopLoop, memory_order_relaxed)) {
            if (anyBreakEnabled()) {
                svcSleepThread(1000000ull);
                if (g_Attached && !atomic_load_explicit(&g_StopLoop, memory_order_relaxed)) {
                    rearmAllBreaks();
                }
            }
        }
    }
}

/* ---- public API -------------------------------------------------------- */

void nxusDebugInit(void) {
    mutexInit(&g_Mutex);
    memset(g_Breaks, 0, sizeof(g_Breaks));
    memset(g_Hits, 0, sizeof(g_Hits));
    memset(g_Threads, 0, sizeof(g_Threads));
    g_Config.style = NXUS_WATCH_STYLE_DEFAULT;
    /* GDB-style by default: a breakpoint hit stops the title and keeps it stopped
       until the PC sends DebugContinue/DebugStep.  A client that wants the old
       "record the hit and keep running" behaviour sets auto_continue = 1 in
       NxusDebugConfig. */
    g_Config.auto_continue = 0;
    atomic_init(&g_Is64Bit, false);
    g_Attached = false;
    g_Debug = INVALID_HANDLE;
    atomic_init(&g_StopLoop, true);
    if (!g_EventMutexReady) {
        rmutexInit(&g_EventMutex);
        g_EventMutexReady = true;
    }
    atomic_init(&g_ExitSeen, false);
    atomic_init(&g_HandoffBusy, false);
    atomic_init(&g_DebugOpUsers, 0);
    atomic_init(&g_DebugClosing, false);
    atomic_init(&g_Stopped, false);
    atomic_init(&g_StoppedThread, 0);
    atomic_init(&g_StopReason, (unsigned)StopReason_Hit);
    atomic_init(&g_StopSeq, 0u);
    atomic_init(&g_ExceptionSeq, 0u);
}

void nxusDebugExit(void) {
    nxusDebugDetach();
}

bool nxusDebugIsAttached(void) { return g_Attached; }

bool nxusDebugExitedPending(void) {
    return atomic_load_explicit(&g_ExitSeen, memory_order_relaxed);
}

bool nxusDebugIsHandoff(void) {
    return atomic_load_explicit(&g_HandoffBusy, memory_order_relaxed);
}

Result nxusDebugAttach(u64 pid) {
    if (g_Attached) return 0;
    if (pid == 0) return (Result)NXUS_MAKE_RESULT(NXUS_ERR_NO_PROCESS);
    /* A session whose debugee exited is collected by nxusServerTick() (the event
       thread cannot join itself).  Starting a second session before that would
       overwrite g_EventThread/g_Debug and leak both. */
    if (g_EventThreadLive || atomic_load_explicit(&g_ExitSeen, memory_order_relaxed)) {
        NXUS_LOG("debug attach: the previous session is still being released");
        return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BUSY);
    }

    /* While we take the process over, a concurrent scan read that fails must not
       auto-reopen dmnt and race the hand-off.  Restored on every failure path and
       on detach. */
    nxusDmntSetAutoReopen(false);
    atomic_store_explicit(&g_HandoffBusy, true, memory_order_release);

    /* Ask for the process FIRST.
     *
     * The old order (ForceClose dmnt -> sleep -> DebugActiveProcess) destroyed
     * dmnt's cheat session, frozen values and toggles *before* finding out
     * whether we could take the process at all: when another debugger already
     * holds it the kernel refuses DebugActiveProcess, so the only thing that
     * attach achieved was breaking the other tool.  dmnt:cht is a single shared
     * cheat process, so asking the kernel first costs one failed call in the
     * "dmnt owns it" case and touches nothing in the "someone else owns it"
     * case. */
    Handle debug = INVALID_HANDLE;
    Result rc = svcDebugActiveProcess(&debug, pid);
    if (R_FAILED(rc)) {
        bool has_cheat_process = false;
        if (R_SUCCEEDED(nxusDmntHasCheatProcess(&has_cheat_process)) && has_cheat_process) {
            /* dmnt itself is the holder (it opens the debug handle for its cheat
               VM), so closing it is the documented hand-off and nobody else is
               debugging this process. */
            Result crc = nxusDmntForceClose();
            NXUS_RESULT("dmnt ForceCloseCheatProcess", crc);
            svcSleepThread(200000000ull);
            rc = svcDebugActiveProcess(&debug, pid);
        }
    }
    g_LastResult = (s32)rc;
    NXUS_RESULT("svcDebugActiveProcess", rc);
    if (R_FAILED(rc)) {
        /* dmnt was never closed unless it owned the process, so there is nothing
           to restore in the common failure case; ForceOpen is cheap and makes the
           "dmnt owned it and the retry still failed" path recover. */
        nxusDmntForceOpen();
        nxusDmntSetAutoReopen(true);
        atomic_store_explicit(&g_HandoffBusy, false, memory_order_release);
        return rc;
    }

    /* The kernel does not reset the breakpoint/watchpoint registers when a
       previous debug handle is closed.  We are the owner now, so leftover slots
       from an earlier session (or from a previously released debugger) can be
       wiped without harming anyone else. */
    clearAllHardwareSlots();

    g_Debug = debug;
    g_Attached = true;
    g_BreakCount = 0;
    g_ThreadCount = 0;
    /* A stop left over from a previous session must not make the event loop hold
       the DebuggerAttached/CreateProcess burst and freeze the fresh attach. */
    clearStopState();
    atomic_store_explicit(&g_ExitSeen, false, memory_order_relaxed);
    atomic_store_explicit(&g_StopLoop, false, memory_order_relaxed);

    armContextIdBreakpoint();

    alignas(0x1000) static u8 eventStack[0x8000];
    rc = threadCreate(&g_EventThread, eventThread, NULL, eventStack, sizeof(eventStack), 0x2A, -2);
    if (R_FAILED(rc)) {
        atomic_store_explicit(&g_StopLoop, true, memory_order_relaxed);
        svcCloseHandle(g_Debug);
        g_Debug = INVALID_HANDLE;
        g_Attached = false;
        /* armContextIdBreakpoint() already programmed the link slot: do not
           leave it behind when the event thread cannot be created. */
        clearAllHardwareSlots();
        nxusDmntForceOpen();
        nxusDmntSetAutoReopen(true);
        atomic_store_explicit(&g_HandoffBusy, false, memory_order_release);
        return rc;
    }
    g_EventThreadLive = true;
    threadStart(&g_EventThread);
    atomic_store_explicit(&g_HandoffBusy, false, memory_order_release);
    NXUS_LOG("debug mode active (pid=%llu, watch style=%u)", (unsigned long long)pid,
             (unsigned)g_Config.style);
    return 0;
}

Result nxusDebugDetach(void) {
    if (!g_Attached && !g_EventThreadLive) {
        atomic_store_explicit(&g_ExitSeen, false, memory_order_relaxed);
        nxusDmntSetAutoReopen(true);
        return 0;
    }

    /* Handing the process back to dmnt: block the auto-reopen/identity paths
       until ForceOpen() has run, otherwise a concurrent read failure re-opens
       dmnt underneath us. */
    atomic_store_explicit(&g_HandoffBusy, true, memory_order_release);

    /* Stop and JOIN the event thread FIRST.  Once threadWaitForExit() returns,
       no thread can be inside rearmAllBreaks()/disarmAllBreaks() any more, so the
       register wipe below can never race with an in-flight re-arm that would put
       a breakpoint back after detach. */
    atomic_store_explicit(&g_StopLoop, true, memory_order_relaxed);

    if (g_EventThreadLive) {
        threadWaitForExit(&g_EventThread);
        threadClose(&g_EventThread);
        g_EventThreadLive = false;
    }

    /* g_Attached=false and the register wipe happen under g_Mutex, in that order:
       nxusDebugSetBreak() re-checks g_Attached while holding the same mutex just
       before it programs a slot, so it either wins (and detach sees the table
       entry and wipes the slot) or loses and returns NXUS_ERR_NOT_ATTACHED.
       Without the ordering an arm could land after the wipe and leave a live
       breakpoint in a process nobody is debugging. */
    mutexLock(&g_Mutex);
    for (u32 i = 0; i < NXUS_DEBUG_MAX_BREAKS; i++) {
        g_Breaks[i].enabled = 0;
        g_Breaks[i].hits_in_window = 0;
        g_Breaks[i].window_start_tick = 0;
    }
    g_BreakCount = 0;
    g_Attached = false;
    /* All ten slots (0..5 plus 0x10..0x13) on all four cores: the ContextID link
       source (4/5) included, because armContextIdBreakpoint() programs it for
       every style.  No conditional "if enabled" here: a stale register is
       invisible to the break table but still fires. */
    clearAllHardwareSlots();
    mutexUnlock(&g_Mutex);

    /* Nothing is held once the session is gone; a stale stop would make the next
       attach believe the target is frozen. */
    clearStopState();
    atomic_store_explicit(&g_ExitSeen, false, memory_order_relaxed);

    if (g_Debug != INVALID_HANDLE) {
        /* Drain the queue and acknowledge every pending exception as handled
           before closing: unread breakpoint events would otherwise be delivered
           as fatal exceptions when the process is resumed by the close. */
        DebugEventInfo ev;
        for (u32 n = 0; n < 256; n++) {
            memset(&ev, 0, sizeof(ev));
            if (R_FAILED(svcGetDebugEvent(&ev, g_Debug))) break;
        }
        Result crc = svcContinueDebugEvent(g_Debug, 4u | 2u | 1u, NULL, 0);
        if (R_FAILED(crc) && !isDebugBusyResult(crc)) {
            NXUS_RESULT("ContinueDebugEvent (detach ack)", crc);
        }

        /* Wait for in-flight svcRead/Write/QueryDebugProcessMemory calls: the
           handle number is reusable the moment it is closed. */
        atomic_store_explicit(&g_DebugClosing, true, memory_order_release);
        for (int wait = 0; wait < 500; wait++) {
            if (atomic_load_explicit(&g_DebugOpUsers, memory_order_acquire) == 0) break;
            svcSleepThread(1000000ull);
        }
        svcCloseHandle(g_Debug);   /* detaches and resumes the target */
        atomic_store_explicit(&g_DebugClosing, false, memory_order_release);
        g_Debug = INVALID_HANDLE;
    }

    /* dmnt may still be tearing the old cheat process down: give it 50 ms, then
       one 100 ms retry instead of leaving the cheat VM closed for the session. */
    svcSleepThread(50000000ull);
    Result rc = nxusDmntForceOpen();
    if (R_FAILED(rc)) {
        NXUS_LOG("dmnt ForceOpenCheatProcess first attempt rc=0x%08X - retrying in 100 ms",
                 (unsigned)rc);
        svcSleepThread(100000000ull);
        rc = nxusDmntForceOpen();
    }
    NXUS_RESULT("dmnt ForceOpenCheatProcess (restore)", rc);
    nxusDmntSetAutoReopen(true);
    atomic_store_explicit(&g_HandoffBusy, false, memory_order_release);
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
    /* The wire layout only carries the low half here; the full id travels in the
       NxusEvent_DebugStopped payload. */
    out->stopped_thread_low = (u32)(nxusDebugStoppedThread() & 0xFFFFFFFFull);
    mutexLock(&g_Mutex);
    out->hit_count = g_HitTotal;
    mutexUnlock(&g_Mutex);
}

Result nxusDebugSetBreak(const NxusBreakRequest *request) {
    /* A size outside {1,2,4,8} makes watchBas() shift by more than 63 bits (and
       wraps its u32 arithmetic), so reject it before any control word is built. */
    if (request != NULL && (request->size != 1 && request->size != 2 &&
                            request->size != 4 && request->size != 8)) {
        return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE);
    }
    if (request == NULL) return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE);

    /* Serialised against detach (and against nxusDebugClearBreak): the whole
       reserve-then-arm sequence runs under g_Mutex, and the session is re-checked
       inside it, so an arm can never land after nxusDebugDetach() wiped the
       registers.  Draining events must not happen here (recordHit() takes this
       same non-recursive mutex). */
    mutexLock(&g_Mutex);
    if (!g_Attached || g_Debug == INVALID_HANDLE ||
        atomic_load_explicit(&g_StopLoop, memory_order_relaxed)) {
        mutexUnlock(&g_Mutex);
        return (Result)NXUS_MAKE_RESULT(NXUS_ERR_NOT_ATTACHED);
    }

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
    if (slot == 0xFFFFFFFFu) {
        mutexUnlock(&g_Mutex);
        return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BUSY);
    }

    /* Reserve the table entry BEFORE the hardware is touched.  Arming first and
       storing afterwards is what left an armed, untracked slot behind whenever the
       table was full (it used to be smaller than the hardware: 8 < 10), and an
       untracked slot can neither be listed nor cleared.  A full table is reported
       as BUSY without any syscall. */
    BreakSlot *entry = findBreakBySlot(slot);
    BreakSlot  previous;
    bool       is_new = false;
    memset(&previous, 0, sizeof(previous));
    if (entry == NULL) {
        if (g_BreakCount >= NXUS_DEBUG_MAX_BREAKS) {
            mutexUnlock(&g_Mutex);
            return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BUSY);
        }
        entry = &g_Breaks[g_BreakCount++];
        is_new = true;
    } else {
        previous = *entry;
    }

    const u32 size = request->size ? request->size : 4;
    const u64 ctrl = request->ctrl ? request->ctrl
                                   : nxusDebugBuildControl(request->kind, size,
                                                           request->address, g_Config.style);
    /* DBGWVR/DBGBVR must hold the aligned word: the byte mask lives in BAS.
       An unaligned value loses the high BAS bits and never fires.  The original
       address is kept in BreakSlot so hits can be reported in user terms. */
    const u64 hw_addr = hwBreakValue(request->kind, request->address);
    entry->slot = slot;
    entry->kind = request->kind;
    entry->size = size;
    entry->address = request->address;
    entry->ctrl = ctrl;
    entry->enabled = 1;
    entry->hits_in_window = 0;
    entry->window_start_tick = 0;

    Result rc = setHardwareBreakPointAllCores(slot, ctrl, hw_addr);
    g_LastResult = (s32)rc;
    if (R_FAILED(rc)) {
        /* Put the table back: nothing may claim a slot the kernel refused.  The
           kernel may also have programmed a subset of the cores before the error,
           so the slot is restored (or wiped when the entry was auto-disarmed) to
           keep the table and the hardware in agreement. */
        if (is_new) {
            g_BreakCount--;
            memset(&g_Breaks[g_BreakCount], 0, sizeof(g_Breaks[0]));
        } else {
            *entry = previous;
        }
        if (previous.enabled) {
            setHardwareBreakPointAllCores(previous.slot, previous.ctrl,
                                          hwBreakValue(previous.kind, previous.address));
        } else {
            setHardwareBreakPointAllCores(slot, 0, 0);
        }
        mutexUnlock(&g_Mutex);
        NXUS_LOG("set break slot=%u kind=%u addr=%08llX hw=%08llX ctrl=%08llX rc=0x%08X",
                 (unsigned)slot, (unsigned)request->kind,
                 (unsigned long long)request->address,
                 (unsigned long long)hw_addr, (unsigned long long)ctrl, (unsigned)rc);
        return rc;
    }

    /* Every execution breakpoint and watchpoint links to the ContextID slot.  If
       the last breakpoint was auto-disarmed, that slot is clear too; without
       re-arming it here the newly set breakpoint silently never fires.  The
       session is re-checked under the mutex, so a detach that got here first is
       respected instead of being undone. */
    if (g_Attached && g_Debug != INVALID_HANDLE &&
        !atomic_load_explicit(&g_StopLoop, memory_order_relaxed)) {
        armContextIdBreakpoint();
    }
    mutexUnlock(&g_Mutex);

    NXUS_LOG("set break slot=%u kind=%u addr=%08llX hw=%08llX ctrl=%08llX rc=0x%08X",
             (unsigned)slot, (unsigned)request->kind, (unsigned long long)request->address,
             (unsigned long long)hw_addr, (unsigned long long)ctrl, (unsigned)rc);
    return 0;
}

Result nxusDebugClearBreak(u32 slot) {
    /* Only real breakpoint/watchpoint slots may be cleared.  In particular the
       ContextID link slot (4 or 5) must keep its breakpoint: clearing it silently
       unlinks every execution breakpoint and they stop firing. */
    const bool is_bp_slot = (slot <= 5);
    const bool is_wp_slot = (slot >= 0x10 && slot <= 0x13);
    if (!is_bp_slot && !is_wp_slot) {
        return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE);
    }
    if (is_bp_slot && slot == styleLinkSlot(g_Config.style)) {
        return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE);
    }

    /* Same serialisation as SetBreak, for the same reason: a clear that runs
       concurrently with detach could reprogram (here: wipe) a register after the
       detach wiped them, and a clear that loses the race must not touch the
       hardware at all. */
    mutexLock(&g_Mutex);
    if (!g_Attached || g_Debug == INVALID_HANDLE ||
        atomic_load_explicit(&g_StopLoop, memory_order_relaxed)) {
        mutexUnlock(&g_Mutex);
        return (Result)NXUS_MAKE_RESULT(NXUS_ERR_NOT_ATTACHED);
    }

    Result rc = setHardwareBreakPointAllCores(slot, 0, 0);
    g_LastResult = (s32)rc;

    for (u32 i = 0; i < g_BreakCount; i++) {
        if (g_Breaks[i].slot == slot) {
            g_Breaks[i] = g_Breaks[g_BreakCount - 1];
            g_BreakCount--;
            break;
        }
    }
    mutexUnlock(&g_Mutex);

    /* A thread may be stopped on the exception this slot produced.  In
       auto-continue mode the target has to be resumed, otherwise it stays frozen
       until another Continue happens to arrive (and the next Continue hits
       ResultBusy 0xF401).  While a GDB-style stop is published, however, removing
       a breakpoint must NOT resume the title: the stop is what the user is
       looking at. */
    if (g_Attached && g_Debug != INVALID_HANDLE && !nxusDebugIsStopped()) {
        drainDebugEvents(NULL);
        for (int retry = 0; retry < 4; retry++) {
            Result crc = svcContinueDebugEvent(g_Debug, 4u | 2u | 1u, NULL, 0);
            if (R_SUCCEEDED(crc)) break;
            if (!isDebugBusyResult(crc)) {
                NXUS_RESULT("ContinueDebugEvent (break clear)", crc);
                break;
            }
            bool extra_break = false;
            if (drainDebugEvents(&extra_break) == 0) {
                svcSleepThread(1000000ull);
            }
        }
    }
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

/* One svcContinueDebugEvent with the flags the working reference implementation
   uses on hardware (4|2|1 = ContinueAll | ContinueOthers | IgnoreException, no
   tid list).  The kernel refuses the call with ResultBusy (0xF401) while even one
   debug event is still queued and then resumes NOTHING, so the queue is drained
   and the call retried instead of leaving the title stopped. */
static Result continueAllOnce(void) {
    if (g_EventMutexReady) rmutexLock(&g_EventMutex);
    Result rc = 0;
    for (int retry = 0; retry < 8; retry++) {
        rc = svcContinueDebugEvent(g_Debug, 4u | 2u | 1u, NULL, 0);
        if (R_SUCCEEDED(rc)) {
            if (g_EventMutexReady) rmutexUnlock(&g_EventMutex);
            return 0;
        }
        if (!isDebugBusyResult(rc)) break;
        if (drainDebugEvents(NULL) == 0) svcSleepThread(1000000ull);
    }
    if (g_EventMutexReady) rmutexUnlock(&g_EventMutex);
    return rc;
}

bool nxusDebugIsStopped(void) {
    /* Acquire: publishStopState() stores the flag with release after it wrote the
       thread and the reason, so a caller that sees true also sees a consistent
       stop record. */
    return atomic_load_explicit(&g_Stopped, memory_order_acquire);
}

u64 nxusDebugStoppedThread(void) {
    return (u64)atomic_load_explicit(&g_StoppedThread, memory_order_relaxed);
}

bool nxusDebugSetAutoContinue(u32 enabled) {
    const bool want = (enabled != 0);
    const bool was = (g_Config.auto_continue != 0);
    g_Config.auto_continue = want ? 1u : 0u;
    if (want == was) return true;

    NXUS_LOG("debug: auto_continue=%u", (unsigned)g_Config.auto_continue);

    /* Switching back to auto-continue while the stop mode is holding the target
       has to release it here: the event loop only ever resumes the process from a
       fresh debug event, so nothing else would send the pending Continue. */
    if (want && g_Attached && nxusDebugIsStopped()) {
        Result rc = nxusDebugContinueAll();
        if (R_FAILED(rc)) {
            NXUS_RESULT("debug: resume after auto_continue=1", rc);
            return false;
        }
    }
    return true;
}

Result nxusDebugContinueAll(void) {
    if (!g_Attached || g_Debug == INVALID_HANDLE) {
        return (Result)NXUS_MAKE_RESULT(NXUS_ERR_NOT_ATTACHED);
    }

    /* 1. Drain first: with one unread event in m_event_info_list the kernel refuses
          ContinueDebugEvent with ResultBusy (0xF401) and resumes NOTHING, which
          left the title frozen after a manual continue. */
    drainDebugEvents(NULL);

    /* Any stop published by that drain belongs to the exception we are about to
       acknowledge, so the sequence number is taken only now. */
    const unsigned stop_seq = atomic_load_explicit(&g_StopSeq, memory_order_relaxed);

    /* 2. An armed slot would trap on the very instruction it already trapped on
          (the PC never advanced past it), so clear every hardware slot first. */
    disarmAllBreaks();

    /* 3. Acknowledge the exception and resume every thread. */
    Result rc = continueAllOnce();

    /* 4. Give the core 1 ms to retire the instruction the breakpoint stopped on. */
    svcSleepThread(1000000ull);

    /* 5. Re-arm what is still enabled.  rearmAllBreaks() is a no-op once a detach
          has started, so a late re-arm can never reprogram a wiped core. */
    rearmAllBreaks();

    /* 6. The stop is over - unless the continue failed (the exception is still
          unacknowledged, so the target really is stopped and the PC must be able
          to retry), or a new hit published its own stop while the slots were going
          back in (that stop is the one the user is looking at). */
    if (R_SUCCEEDED(rc) &&
        atomic_load_explicit(&g_StopSeq, memory_order_relaxed) == stop_seq) {
        clearStopState();
    }

    g_LastResult = (s32)rc;
    if (R_FAILED(rc)) NXUS_RESULT("ContinueDebugEvent (continue)", rc);
    return rc;
}

/* Atmosphère's ThreadContextFlag_SetSingleStep (bit 1).  The kernel only accepts
   it when MESOSPHERE_ENABLE_HARDWARE_SINGLE_STEP is compiled in; on the stock
   kernel the call fails with InvalidEnumValue and nxusDebugStep() falls back. */
#define NXUS_DEBUG_CTX_FLAG_SET_SINGLE_STEP 2u
/* Upper bound for "the exception that stopped the target again has arrived". */
#define NXUS_DEBUG_STOP_WAIT_MS 20u

/* Bounded wait for the exception that stopped the target again.  seq_before is
   read BEFORE the continue; anything that bumps g_ExceptionSeq afterwards (an
   exception consumed by our own drain or by the event thread) proves that the
   kernel delivered one.  Returns false when nothing arrived in time. */
static bool waitForStopException(unsigned seq_before, u32 timeout_ms) {
    for (u32 elapsed = 0; elapsed < timeout_ms; elapsed++) {
        drainDebugEvents(NULL);
        if (atomic_load_explicit(&g_ExceptionSeq, memory_order_relaxed) != seq_before) {
            return true;
        }
        svcSleepThread(1000000ull);
    }
    return false;
}

/* Resume the target for "one instruction" and guarantee that it is stopped again
   before returning.  Both step paths use this, so the stop published for the PC is
   always truthful:
     - hardware_step: the kernel's single-step exception IS the stop;
     - fallback (no hardware single step): the target runs for ~2 ms and is stopped
       again with svcBreakDebugProcess, whose DebuggerBreak exception is drained.
   The breaks are disarmed before the continue and re-armed only after the stop has
   been confirmed: a slot left armed would trap on the very instruction the PC never
   advanced past, and the title would freeze in a trap loop instead of stepping. */
static Result stepResumeAndStop(bool hardware_step) {
    const unsigned exc_before = atomic_load_explicit(&g_ExceptionSeq, memory_order_relaxed);

    disarmAllBreaks();
    drainDebugEvents(NULL);
    Result rc = continueAllOnce();
    if (R_FAILED(rc)) {
        /* Nothing was acknowledged: the target really is still stopped, so the
           slots can go back in and the PC can retry. */
        rearmAllBreaks();
        NXUS_RESULT("ContinueDebugEvent (step)", rc);
        return rc;
    }

    bool stopped = false;
    if (hardware_step) {
        stopped = waitForStopException(exc_before, NXUS_DEBUG_STOP_WAIT_MS);
        if (!stopped) {
            NXUS_LOG("debug step: no single-step exception within %u ms - forcing a stop",
                     (unsigned)NXUS_DEBUG_STOP_WAIT_MS);
        }
    }
    if (!stopped) {
        /* Give the core time to retire at least one instruction before stopping it
           again (the fallback cannot do better than "approximately one"). */
        svcSleepThread(2000000ull);
        rc = svcBreakDebugProcess(g_Debug);
        if (R_FAILED(rc)) {
            /* No confirmed stop, so the slots stay clear: re-arming now could trap
               a running target on its next instruction.  The stop state stays
               published and the PC can retry. */
            NXUS_RESULT("svcBreakDebugProcess (step stop)", rc);
            return rc;
        }
        const unsigned brk_before = atomic_load_explicit(&g_ExceptionSeq, memory_order_relaxed);
        if (!waitForStopException(brk_before, NXUS_DEBUG_STOP_WAIT_MS)) {
            NXUS_LOG("debug step: no DebuggerBreak event within %u ms after the forced stop",
                     (unsigned)NXUS_DEBUG_STOP_WAIT_MS);
        }
    }

    /* The target is stopped again, so programming the slots cannot retrap. */
    rearmAllBreaks();
    return 0;
}

Result nxusDebugStep(u64 thread_id) {
    if (!g_Attached || g_Debug == INVALID_HANDLE) {
        return (Result)NXUS_MAKE_RESULT(NXUS_ERR_NOT_ATTACHED);
    }

    u64 tid = thread_id;
    if (tid == 0) tid = nxusDebugStoppedThread();
    if (tid == 0) {
        /* No stop was recorded (a manual break carries no single owner): step the
           first thread the kernel reports for the process. */
        u64 ids[1];
        s32 num = 0;
        memset(ids, 0, sizeof(ids));
        if (R_SUCCEEDED(svcGetThreadList(&num, ids, 1, g_Debug)) && num > 0) tid = ids[0];
    }
    if (tid == 0) {
        NXUS_LOG("debug step: no thread to single-step");
        return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE);
    }

    /* The stop stays published for the whole step, through publishStopState() so
       g_StopSeq moves like it does for a hit: the PC keeps seeing a stopped target
       and can issue the next step right away.  A step is an explicit debugger
       action, hence StopReason_Step (honoured even in auto-continue mode). */
    publishStopState(tid, StopReason_Step);

    /* Preferred path: the kernel's own hardware single step.  Setting the flag on
       a copy of the current context keeps every register intact; the kernel then
       executes exactly one instruction and raises a debug exception, which the
       event loop holds because the stop above is still published. */
    u64 pc_before = 0;
    bool have_context = false;
    bool hardware_step = false;
    ThreadContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    Result rc = svcGetDebugThreadContext(&ctx, g_Debug, tid, RegisterGroup_CpuAll);
    if (R_SUCCEEDED(rc)) {
        have_context = true;
        pc_before = ctx.pc.x;
        rc = svcSetDebugThreadContext(g_Debug, tid, &ctx,
                                      NXUS_DEBUG_CTX_FLAG_SET_SINGLE_STEP);
        hardware_step = R_SUCCEEDED(rc);
        if (!hardware_step) {
            NXUS_LOG("debug step: SetThreadContext(SingleStep) rc=0x%08X - using fallback",
                     (unsigned)rc);
        }
    } else {
        NXUS_LOG("debug step: GetThreadContext rc=0x%08X - using fallback", (unsigned)rc);
    }

    rc = stepResumeAndStop(hardware_step);
    g_LastResult = (s32)rc;
    if (R_FAILED(rc)) return rc;

    /* Report where the step landed.  The stop event is re-sent with the new PC so
       the PC does not have to poll for it, and a step that did not actually move
       the PC is called out instead of being reported as a successful step. */
    u64 pc_after = pc_before;
    ThreadContext after;
    memset(&after, 0, sizeof(after));
    if (R_SUCCEEDED(svcGetDebugThreadContext(&after, g_Debug, tid, RegisterGroup_CpuAll))) {
        pc_after = after.pc.x;
    }
    if (have_context && pc_after == pc_before) {
        NXUS_LOG("debug step: WARNING pc did not advance (thread=%016llX pc=%016llX) - "
                 "the target may have stopped on the same instruction",
                 (unsigned long long)tid, (unsigned long long)pc_before);
    }

    publishStopState(tid, StopReason_Step);
    sendStopEvent(tid, pc_after, 0, 0xFFFFFFFFu, 0xFFFFFFFFu);
    NXUS_LOG("debug step: %s thread=%016llX pc=%016llX -> %016llX",
             hardware_step ? "hardware single step" : "fallback (no hardware single step)",
             (unsigned long long)tid, (unsigned long long)pc_before,
             (unsigned long long)pc_after);
    return 0;
}

Result nxusDebugBreak(void) {
    if (!g_Attached || g_Debug == INVALID_HANDLE) {
        return (Result)NXUS_MAKE_RESULT(NXUS_ERR_NOT_ATTACHED);
    }

    /* Publish the stop BEFORE the break: the kernel pushes a DebuggerBreak
       exception, and the event loop must hold that event instead of acknowledging
       it immediately (it also holds it in auto-continue mode, because a manual
       pause is explicit).  Going through publishStopState() keeps g_StopSeq in
       step with the stop, which ContinueAll relies on. */
    const bool was_stopped = nxusDebugIsStopped();
    const u64 was_thread = nxusDebugStoppedThread();
    const unsigned was_reason = atomic_load_explicit(&g_StopReason, memory_order_relaxed);
    publishStopState(0, StopReason_Manual);

    Result rc = svcBreakDebugProcess(g_Debug);
    g_LastResult = (s32)rc;
    if (R_FAILED(rc)) {
        /* The break did not happen: do not keep the stop we just published (or the
           one that was already there). */
        if (was_stopped) {
            atomic_store_explicit(&g_StoppedThread, was_thread, memory_order_relaxed);
            atomic_store_explicit(&g_StopReason, was_reason, memory_order_relaxed);
        } else {
            clearStopState();
        }
        NXUS_RESULT("svcBreakDebugProcess", rc);
        return rc;
    }

    NXUS_LOG("debug: break requested - target stopped");
    /* Manual break: no breakpoint/kind behind it. */
    sendStopEvent(0, 0, 0, 0xFFFFFFFFu, 0xFFFFFFFFu);
    return 0;
}

Result nxusDebugReadMemory(u64 address, void *buffer, u32 size) {
    Result rc = debugOpBegin();
    if (R_FAILED(rc)) return rc;
    rc = svcReadDebugProcessMemory(buffer, g_Debug, address, size);
    debugOpEnd();
    return rc;
}

Result nxusDebugWriteMemory(u64 address, const void *buffer, u32 size) {
    Result rc = debugOpBegin();
    if (R_FAILED(rc)) return rc;
    rc = svcWriteDebugProcessMemory(g_Debug, buffer, address, size);
    debugOpEnd();
    return rc;
}

Result nxusDebugQueryMemory(u64 address, NxusMemoryInfo *out) {
    if (out == NULL) return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE);
    Result begin_rc = debugOpBegin();
    if (R_FAILED(begin_rc)) return begin_rc;

    MemoryInfo info;
    u32 page_info = 0;
    memset(&info, 0, sizeof(info));
    Result rc = svcQueryDebugProcessMemory(&info, &page_info, g_Debug, address);
    if (R_FAILED(rc)) { debugOpEnd(); return rc; }

    out->base_addr = info.addr;
    out->size = info.size;
    out->memory_type = info.type;
    out->memory_attribute = info.attr;
    out->perm = info.perm;
    out->device_refcount = info.device_refcount;
    out->ipc_refcount = info.ipc_refcount;
    out->padding = 0;
    debugOpEnd();
    return 0;
}

void nxusDebugConfigure(const NxusDebugConfig *config) {
    if (config == NULL) return;
    if (config->style <= NXUS_WATCH_STYLE_LINK6) g_Config.style = config->style;
    /* auto_continue = 0 (default) is GDB-style stop-on-hit; the setter also
       releases a target that is currently held when the mode is switched back. */
    nxusDebugSetAutoContinue(config->auto_continue);
    if (g_Attached && !atomic_load_explicit(&g_StopLoop, memory_order_relaxed)) {
        armContextIdBreakpoint();
    }
}

void nxusDebugGetConfig(NxusDebugConfig *out) {
    if (out != NULL) *out = g_Config;
}
