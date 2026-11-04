/*
 * Nxus console-side cheat service - see switch/include/nxus_cheat_srv.h for the
 * contract, the memory budget and the threading/lock rules.
 *
 * Shape of the file
 * -----------------
 *   1. static state (program, journal, worker, stamps, status snapshot)
 *   2. the IO adapter handed to the interpreter (dmnt + the same range checks the
 *      NxusCmd_Write handler uses for NXUS_WRITE_FLAG_ALLOW_RX)
 *   3. target identity: sample / compare / stop-everything
 *   4. journal restore accounting
 *   5. the worker step and the fixed-period worker loop
 *   6. the seven entry points nxus_cheat_srv.h declares
 *
 * The interpreter (core/nxus_cheatvm.c) owns all opcode semantics; nothing here
 * decodes an instruction.
 */

#include "nxus_cheat_srv.h"

#include "nxus_debug.h"
#include "nxus_dmntcht.h"
#include "nxus_hid.h"
#include "nxus_log.h"
#include "nxus_net.h"
#include "nxus_server.h"
#include "nxus_session.h"

#include <stdalign.h>
#include <stdatomic.h>
#include <string.h>

/* ---- static footprint ---------------------------------------------------
 * Nothing in this file allocates: the sysmodule's 8 MiB inner heap already holds
 * the scan chunk, the hit list and up to two snapshot slots.  The two big blocks
 * are the interpreter's program and its journal, both sized by core/nxus_cheatvm.h.
 * The asserts below are deliberately UPPER bounds plus one total: raising a core
 * cap is fine as long as the reservation stays inside the documented budget, and
 * the build stops if it does not.
 *
 * Measured on the shipped caps: program 17592 B, journal 12296 B, stack 8192 B,
 * total 38080 B.  Note that the interpreter's own caps, not this file, set that
 * number: 512 instructions x 24 B is 12 KiB on its own, and a 24-byte journal entry
 * x 512 is another 12 KiB, so the program+journal pair is ~30 KiB before the stack.
 * The asserts below pin the real footprint instead of a figure the types cannot
 * meet, and they are upper bounds so a future core cap that grows either structure
 * fails the build here rather than silently taking more of the sysmodule's memory. */
static NxusCheatProgram g_Program;
static NxusCheatJournal g_Journal;
static alignas(0x1000) u8 g_WorkerStack[0x2000];

#define CHEATSRV_STATIC_MAX_BYTES (40u * 1024u)
NXUS_STATIC_ASSERT(sizeof(NxusCheatProgram) <= 20u * 1024u,
                   "NxusCheatProgram must stay inside the cheat service budget");
NXUS_STATIC_ASSERT(sizeof(NxusCheatJournal) <= 16u * 1024u,
                   "NxusCheatJournal must stay inside the cheat service budget");
NXUS_STATIC_ASSERT(sizeof(NxusCheatProgram) + sizeof(NxusCheatJournal) + sizeof(g_WorkerStack)
                       <= CHEATSRV_STATIC_MAX_BYTES,
                   "cheat service static footprint exceeded");

/* Worker thread.  One creator (Init) and one joiner (Exit), both on the boot /
 * exit path, so - unlike the pointer-scan worker - the Thread needs no atomic
 * claim: no command can start or stop it. */
static Thread g_WorkerThread;
static atomic_bool g_WorkerLive;   /* Thread created and started (readers: Status) */
static atomic_bool g_WorkerStop;   /* Exit asked the loop to return */
static atomic_bool g_WorkerDone;   /* the loop left (join may proceed) */
/* Set for the whole of nxusCheatSrvExit() and cleared only by Init.  A client that
 * keeps polling during the teardown must not be able to install a program behind the
 * release (the connection thread outlives this service in main.c's order), the same
 * way nxusServerExit()'s gate refuses everything but Nop. */
static atomic_bool g_Shutdown;
static bool g_Initialized;         /* main thread only */

#define CHEATSRV_WORKER_PRIO 0x2C
#define CHEATSRV_WORKER_CORE (-2)

/* Program + journal + block bookkeeping: one mutex, see the lock-order note in
 * the header.  Created by Init before anything else can touch the state. */
static Mutex g_CheatLock;
static bool  g_LockReady;

static bool g_ProgramLoaded;                                  /* under g_CheatLock */
static u32  g_ConsecutiveFailures[NXUS_CHEATVM_MAX_BLOCKS];    /* under g_CheatLock */
static u32  g_FaultCount;                                     /* under g_CheatLock */
static u32  g_MissedTicks;                                    /* worker thread only */

/* The target a program was uploaded for.  Every tick compares this with the live
 * session identity / dmnt incarnation; a difference stops everything. */
typedef struct {
    u64  pid;
    u64  program_id;
    u32  incarnation;
    bool valid;
} CheatTarget;

static CheatTarget g_Owner;   /* under g_CheatLock */

/* Status snapshot: published under the lock, sampled without it.  A status poll
 * must not wait behind a tick that is inside a dmnt call; the seqlock hands out
 * either the previous or the new complete snapshot, never a blend. */
static NxusCheatStatus g_Status;
static atomic_uint     g_StatusSeq;   /* even = stable, odd = a publish is in flight */
#define CHEATSRV_STATUS_RETRY 16u

static void cheatLock(void) {
    if (g_LockReady) mutexLock(&g_CheatLock);
}

static void cheatUnlock(void) {
    if (g_LockReady) mutexUnlock(&g_CheatLock);
}

static u64 cheatNowNs(void) {
    return armTicksToNs(armGetSystemTick());
}

static u64 cheatNowMs(void) {
    return cheatNowNs() / 1000000ull;
}

/* ======================================================================== */
/* IO adapter (dmnt + the NxusCmd_Write range policy)                       */
/* ======================================================================== */

/*
 * The interpreter calls write() with allow_rx == true for every patch (see
 * core/nxus_cheatvm.c:cheatWriteValue), because cheat codes rewrite Read-Execute
 * .text pages.  This adapter applies the SAME policy as the server's Write handler:
 *
 *   allow_rx -> the range must be readable AND (writable OR executable)
 *               (nxusSessionCheckCodePatchRange: the opt-in NXUS_WRITE_FLAG_ALLOW_RX
 *               escape hatch)
 *   else     -> the range must be readable AND writable
 *               (nxusSessionCheckRange(..., true), the plain-write policy)
 *
 * Both query the LIVE target (dmnt, or the debug session - but the worker is
 * suspended while a debug session owns the process, so dmnt is the one in use), so
 * a freshly reloaded .text is judged as it is now rather than against a scan-time
 * snapshot.
 *
 * One validated range is cached for the duration of a single tick: a loop cheat
 * writes the same address 60 times a second, and re-asking dmnt for the mapping
 * on every store would double the IPC count of the hot path.  The cache is cleared
 * at the start of every tick (and before a journal restore), so a remapped region
 * can never be written through a stale verdict for longer than one tick.
 */
typedef struct {
    bool range_ok;
    u64  range_base;
    u64  range_size;
    u32  ranges_checked;
    u32  writes_ok;
    u32  writes_failed;
} CheatIoState;

static bool cheatIoRangeAllowed(CheatIoState *state, u64 address, u32 size, bool allow_rx) {
    if (state == NULL || size == 0) return false;

    if (state->range_ok && address >= state->range_base) {
        const u64 offset = address - state->range_base;
        if (offset <= state->range_size && (u64)size <= state->range_size - offset) return true;
    }

    const bool ok = allow_rx ? nxusSessionCheckCodePatchRange(address, size)
                             : nxusSessionCheckRange(address, size, true);
    state->ranges_checked++;
    if (ok) {
        state->range_ok = true;
        state->range_base = address;
        state->range_size = size;
    }
    return ok;
}

static int cheatSrvIoRead(void *user, u64 address, void *out, u32 size) {
    (void)user;
    if (out == NULL || size == 0) return -1;
    /* sessionRead picks the live source (dmnt, or the debug handle while we hold
     * one) and returns 0 on success - exactly the convention NxusCheatIo wants. */
    return nxusSessionReadMemory(address, out, size);
}

static int cheatSrvIoWrite(void *user, u64 address, const void *data, u32 size, bool allow_rx) {
    CheatIoState *state = (CheatIoState *)user;

    if (state == NULL || data == NULL || size == 0) return -1;
    if (!cheatIoRangeAllowed(state, address, size, allow_rx)) {
        state->writes_failed++;
        return -1;
    }
    /* The worker is suspended while a debug session owns the process (see
     * cheatSrvWorkerStep), so dmnt is the writer here - the same call the server's
     * Write handler makes when no debug session is attached. */
    if (R_FAILED(nxusDmntWrite(address, data, size))) {
        state->writes_failed++;
        return -1;
    }
    state->writes_ok++;
    return 0;
}

static void cheatIoInit(CheatIoState *state, NxusCheatIo *io) {
    memset(state, 0, sizeof(*state));
    io->user = state;
    io->read = cheatSrvIoRead;
    io->write = cheatSrvIoWrite;
}

/* ======================================================================== */
/* Target identity                                                          */
/* ======================================================================== */

static bool cheatTargetSample(CheatTarget *out) {
    NxusTargetIdentity identity;
    if (out == NULL) return false;
    memset(&identity, 0, sizeof(identity));
    if (!nxusSessionTargetIdentity(&identity)) return false;   /* writer won the race */
    out->pid = identity.pid;
    out->program_id = identity.program_id;
    out->incarnation = nxusDmntTargetIncarnation();
    out->valid = true;
    return true;
}

/*
 * Same-target rule, deliberately STRICTER than the hit-list / snapshot owner checks:
 *
 *   - the dmnt target INCARNATION must be equal.  It is the only token that changes
 *     when a title is restarted into a fixed layout (same pid, same title id, same
 *     mappings), and running a cheat across it would patch the new process at the
 *     old addresses,
 *   - a pid of 0 on EITHER side is NOT a match.  The hit-list rule treats 0 as
 *     "unknown, do not refuse", which is right for a list the user can re-scan; a
 *     cheat program must not keep writing when the console has lost the target, so
 *     "no target" ends the program instead of being tolerated,
 *   - both pids must be equal, and the title ids must be equal whenever both sides
 *     know one (a DebugAttach may leave program_id 0 for the session).
 */
static bool cheatTargetSame(const CheatTarget *a, const CheatTarget *b) {
    if (a == NULL || b == NULL) return false;
    if (!a->valid || !b->valid) return false;
    if (a->incarnation != b->incarnation) return false;
    if (a->pid == 0 || b->pid == 0) return false;
    if (a->pid != b->pid) return false;
    return a->program_id == 0 || b->program_id == 0 || a->program_id == b->program_id;
}

/* Disable every block of the installed program.  Returns how many were enabled. */
static u32 cheatDisableAllLocked(void) {
    u32 blocks = g_Program.header.block_count;
    u32 stopped = 0;
    u32 i;

    if (blocks > NXUS_CHEATVM_MAX_BLOCKS) blocks = NXUS_CHEATVM_MAX_BLOCKS;
    for (i = 0; i < blocks; i++) {
        if (g_Program.state[i].enabled) stopped++;
        (void)nxusCheatSetEnabled(&g_Program, i, false);
        g_ConsecutiveFailures[i] = 0;
    }
    return stopped;
}

static void cheatDisableBlockLocked(u32 index) {
    (void)nxusCheatSetEnabled(&g_Program, index, false);
    if (index < NXUS_CHEATVM_MAX_BLOCKS) g_ConsecutiveFailures[index] = 0;
}

/* Restore the journalled originals through the adapter and report what happened.
 * The counters live in the adapter, so a partial failure is reported exactly
 * instead of being inferred from the interpreter's all-or-nothing return value. */
typedef struct {
    u32 restored;
    u32 failed;
} CheatRestoreCount;

static CheatRestoreCount cheatRestoreJournalLocked(void) {
    CheatRestoreCount count;
    CheatIoState state;
    NxusCheatIo io;

    memset(&count, 0, sizeof(count));
    cheatIoInit(&state, &io);
    if (nxusCheatJournalRestore(&g_Journal, &io, true) < 0) {
        NXUS_LOG_DEBUG("cheat: journal restore reported a failed address");
    }
    count.restored = state.writes_ok;
    count.failed = state.writes_failed;
    return count;
}

/* Publish the status snapshot.  Caller holds g_CheatLock (or owns the state
 * exclusively, as Init does before the worker exists). */
static void cheatPublishStatus(void) {
    NxusCheatStatus status;
    u32 blocks = 0;
    u32 i;
    u32 seq;

    memset(&status, 0, sizeof(status));
    if (g_ProgramLoaded) {
        blocks = g_Program.header.block_count;
        if (blocks > NXUS_CHEATVM_MAX_BLOCKS) blocks = NXUS_CHEATVM_MAX_BLOCKS;
        status.program_valid = 1u;
        status.block_count = g_Program.header.block_count;
        status.insn_count = g_Program.header.insn_count;
        status.tick_count = g_Program.tick_count;
    }
    status.journal_count = g_Journal.count;
    status.fault_count = g_FaultCount;
    status.running = atomic_load_explicit(&g_WorkerLive, memory_order_acquire) ? 1u : 0u;
    status.keys_held = nxusHidHeldMask();
    for (i = 0; i < blocks; i++) {
        if (g_Program.state[i].enabled) status.enabled_count++;
        /* Mirror the interpreter's own per-block error: it clears the field on a
         * successful run, so "no block reports an error" really means "the last
         * tick was clean".  The raw (negative) value is published, as the protocol
         * field documents; the upload reply uses the positive encoding. */
        if (status.last_error == 0 && g_Program.state[i].last_error != 0) {
            status.last_error = g_Program.state[i].last_error;
            status.last_error_pc = g_Program.state[i].error_pc;
        }
    }

    seq = atomic_load_explicit(&g_StatusSeq, memory_order_relaxed);
    atomic_store_explicit(&g_StatusSeq, seq + 1u, memory_order_relaxed);   /* odd */
    /* Store/store barrier: on aarch64 the plain stores below could otherwise
       become visible before the odd marker and a reader would accept a blend. */
    atomic_thread_fence(memory_order_release);
    g_Status = status;
    atomic_store_explicit(&g_StatusSeq, seq + 2u, memory_order_release);   /* even */
}

static void cheatSendFault(const NxusCheatFault *fault) {
    Result rc;

    if (fault == NULL) return;
    rc = nxusNetSendEvent(NxusEvent_CheatFault, fault, (u32)sizeof(*fault));
    if (R_FAILED(rc)) {
        /* No client attached (or the link died): the fault still shows up in
         * CheatStatus (fault_count / disabled blocks). */
        NXUS_LOG_DEBUG("cheat: fault event could not be sent (rc=0x%08X)", (unsigned)rc);
    }
}

/* ======================================================================== */
/* Worker                                                                  */
/* ======================================================================== */

static bool cheatWorkerShouldRun(void) {
    if (atomic_load_explicit(&g_WorkerStop, memory_order_acquire)) return false;
    /* The dispatcher's terminal gate: after nxusServerExit() the session and the
     * dmnt wrapper are on their way out, so the worker must not start another tick
     * (this is the belt to Exit's braces - main.c stops this service first). */
    return !nxusServerHasExited();
}

/* One tick: verify the target, run every enabled block through the interpreter,
 * disarm blocks that keep failing.  Exposed to the host test through the file
 * include (it is static on purpose: only the worker may call it in production). */
static void cheatSrvWorkerStep(void) {
    CheatIoState io;
    NxusCheatIo io_iface;
    CheatTarget now;
    NxusCheatFault fault;
    bool have_fault = false;
    u32 blocks;
    u32 before[NXUS_CHEATVM_MAX_BLOCKS];
    u32 i;
    static bool debug_suspended;

    /* While a debug session owns the process dmnt is closed, and this project
     * deliberately suspends the cheat VM for that window (nxus_debug.h: "cheat VM
     * support is suspended while debug mode is active").  Log the two transitions
     * once each so a user is not left wondering why the codes stopped. */
    if (nxusDebugIsAttached()) {
        if (!debug_suspended) {
            debug_suspended = true;
            NXUS_LOG("cheat: debug session holds the process - the cheat worker is suspended");
        }
        return;
    }
    if (debug_suspended) {
        debug_suspended = false;
        NXUS_LOG("cheat: debug session released - the cheat worker resumes");
    }

    cheatLock();
    if (!g_ProgramLoaded || !g_Owner.valid) {
        cheatUnlock();
        return;
    }

    if (!cheatTargetSample(&now)) {
        /* Lost the seqlock race against a writer: no trustworthy identity this
         * tick, and running unverified is exactly what this service must not do. */
        NXUS_LOG_DEBUG("cheat: target identity sample lost the race - tick skipped");
        cheatUnlock();
        return;
    }

    if (!cheatTargetSame(&g_Owner, &now)) {
        /* Target changed: stop everything, write the originals back and tell the
         * PC.  The journal is dropped even when a write failed - those bytes belong
         * to a process that is gone, and retrying them against the NEXT process
         * would patch an unrelated address. */
        const CheatTarget uploaded = g_Owner;
        const u32 stopped = cheatDisableAllLocked();
        const CheatRestoreCount restored = cheatRestoreJournalLocked();

        nxusCheatJournalReset(&g_Journal);
        memset(&g_Owner, 0, sizeof(g_Owner));   /* no further ticks until a re-upload */
        g_FaultCount++;
        cheatPublishStatus();
        cheatUnlock();

        NXUS_LOG("cheat: target changed (pid=%llu title=%016llX incarnation=%u, uploaded for "
                 "pid=%llu title=%016llX incarnation=%u) - %u block(s) stopped, "
                 "%u address(es) restored, %u failed",
                 (unsigned long long)now.pid, (unsigned long long)now.program_id,
                 (unsigned)now.incarnation,
                 (unsigned long long)uploaded.pid, (unsigned long long)uploaded.program_id,
                 (unsigned)uploaded.incarnation,
                 (unsigned)stopped, (unsigned)restored.restored, (unsigned)restored.failed);

        memset(&fault, 0, sizeof(fault));
        fault.reason = NXUS_CHEAT_FAULT_TARGET_GONE;
        fault.block = 0xFFFFFFFFu;
        fault.pc = 0;
        fault.restored = restored.restored;
        cheatSendFault(&fault);
        return;
    }

    blocks = g_Program.header.block_count;
    if (blocks > NXUS_CHEATVM_MAX_BLOCKS) blocks = NXUS_CHEATVM_MAX_BLOCKS;
    for (i = 0; i < blocks; i++) before[i] = g_Program.state[i].execs;

    cheatIoInit(&io, &io_iface);
    /* The HID mask is sampled EVERY tick (the worker owns that read; a user presses
     * the combo long after the upload), and the interpreter decides which blocks
     * run: enabled loop blocks every tick, an enabled patch block once. */
    (void)nxusCheatTick(&g_Program, &io_iface, nxusHidHeldMask(), &g_Journal);

    for (i = 0; i < blocks; i++) {
        const NxusCheatBlockState *state = &g_Program.state[i];
        u32 reason;

        /* execs moved => the interpreter ran this block in this tick; a block that
         * is disabled or already ran its patch keeps its old error fields. */
        if (state->execs == before[i]) continue;
        if (state->last_error == 0) {
            g_ConsecutiveFailures[i] = 0;   /* recovered */
            continue;
        }

        reason = (u32)(-(s32)state->last_error);   /* the documented positive code */
        if (state->last_error == (u32)NXUS_CHEATVM_ERR_WRITE &&
            g_Journal.count >= g_Journal.capacity) {
            /* Out of journal slots: nothing can be patched any more and waiting
             * three ticks would only repeat the same refusal. */
            if (!have_fault) {
                memset(&fault, 0, sizeof(fault));
                fault.reason = NXUS_CHEAT_FAULT_JOURNAL_FULL;
                fault.block = i;
                fault.pc = state->error_pc;
                fault.restored = 0;
                have_fault = true;
            }
            cheatDisableBlockLocked(i);
            NXUS_LOG("cheat: block %u: journal full - block disabled", (unsigned)i);
            continue;
        }

        if (g_ConsecutiveFailures[i] < 0xFFu) g_ConsecutiveFailures[i]++;
        if (g_ConsecutiveFailures[i] < NXUS_CHEATSRV_FAIL_LIMIT) continue;

        if (!have_fault) {
            memset(&fault, 0, sizeof(fault));
            fault.reason = reason;
            fault.block = i;
            fault.pc = state->error_pc;
            fault.restored = 0;
            have_fault = true;
        }
        cheatDisableBlockLocked(i);
        NXUS_LOG("cheat: block %u failed %u tick(s) in a row (err=%d pc=%u) - block disabled",
                 (unsigned)i, (unsigned)NXUS_CHEATSRV_FAIL_LIMIT, (int)state->last_error,
                 (unsigned)state->error_pc);
    }

    if (have_fault) g_FaultCount++;
    cheatPublishStatus();
    cheatUnlock();

    if (have_fault) {
        NXUS_LOG("cheat: block %u stopped by the worker (reason=%u) - sent CheatFault",
                 (unsigned)fault.block, (unsigned)fault.reason);
        cheatSendFault(&fault);
    }
}

/*
 * Fixed-period loop.  `next_due` advances by exactly one period; when a tick
 * overran its slot the periods it missed are dropped (never replayed back to back),
 * so one slow block cannot stretch the cadence for the blocks after it.  In the
 * normal case the sleep is the plain 16 ms of NXUS_CHEATSRV_PERIOD_NS.
 */
static void cheatSrvWorkerMain(void *arg) {
    u64 next_due;

    (void)arg;
    next_due = cheatNowNs() + NXUS_CHEATSRV_PERIOD_NS;

    while (cheatWorkerShouldRun()) {
        u64 now;
        u64 sleep_ns;

        cheatSrvWorkerStep();

        now = cheatNowNs();
        if (next_due <= now) {
            const u64 missed = (now - next_due) / NXUS_CHEATSRV_PERIOD_NS + 1ull;
            next_due += missed * NXUS_CHEATSRV_PERIOD_NS;
            g_MissedTicks += (u32)missed;
            NXUS_LOG_DEBUG("cheat: tick overran its slot - %llu period(s) skipped "
                           "(%u since start)", (unsigned long long)missed,
                           (unsigned)g_MissedTicks);
        }
        sleep_ns = next_due - now;
        if (sleep_ns > NXUS_CHEATSRV_PERIOD_NS) sleep_ns = NXUS_CHEATSRV_PERIOD_NS;
        if (sleep_ns != 0) svcSleepThread((s64)sleep_ns);
    }

    atomic_store_explicit(&g_WorkerDone, true, memory_order_release);
}

/* ======================================================================== */
/* Entry points                                                            */
/* ======================================================================== */

void nxusCheatSrvInit(void) {
    Result trc;

    if (!g_LockReady) {
        mutexInit(&g_CheatLock);
        g_LockReady = true;
    }
    if (g_Initialized) {
        NXUS_LOG_DEBUG("cheat: init called twice - ignored");
        return;
    }

    /* No worker and no command exists yet, so this reset cannot race a reader
     * (Init runs on the boot path, before the listener serves cheat commands). */
    nxusCheatReset(&g_Program);
    nxusCheatJournalReset(&g_Journal);
    memset(&g_Owner, 0, sizeof(g_Owner));
    memset(g_ConsecutiveFailures, 0, sizeof(g_ConsecutiveFailures));
    g_ProgramLoaded = false;
    g_FaultCount = 0;
    g_MissedTicks = 0;
    atomic_store_explicit(&g_WorkerStop, false, memory_order_release);
    atomic_store_explicit(&g_WorkerDone, true, memory_order_release);
    atomic_store_explicit(&g_Shutdown, false, memory_order_release);
    cheatPublishStatus();
    g_Initialized = true;

    trc = threadCreate(&g_WorkerThread, cheatSrvWorkerMain, NULL, g_WorkerStack,
                       sizeof(g_WorkerStack), CHEATSRV_WORKER_PRIO, CHEATSRV_WORKER_CORE);
    if (R_FAILED(trc)) {
        /* Keep the commands usable (upload/status/panic-off all work); only the
         * automatic execution is missing.  Status reports running == 0, so a client
         * can tell. */
        NXUS_RESULT("threadCreate(cheat worker)", trc);
        NXUS_LOG("cheat: no worker thread - programs are accepted but nothing runs");
        g_WorkerLive = false;
        return;
    }

    atomic_store_explicit(&g_WorkerLive, true, memory_order_release);
    /* Cleared BEFORE threadStart(), so the loop can never publish "done" and then
     * be overwritten by this store. */
    atomic_store_explicit(&g_WorkerDone, false, memory_order_release);
    threadStart(&g_WorkerThread);
    NXUS_LOG("cheat: worker started (period %u ms, fail limit %u ticks)",
             (unsigned)(NXUS_CHEATSRV_PERIOD_NS / 1000000ull),
             (unsigned)NXUS_CHEATSRV_FAIL_LIMIT);
}

void nxusCheatSrvExit(void) {
    bool joined = true;

    if (!g_Initialized) return;

    /* Raised before anything is torn down: an upload that lands while this runs
       would install a program nobody will ever execute (and after the release below
       it would even resurrect state the exit just cleared). */
    atomic_store_explicit(&g_Shutdown, true, memory_order_release);
    atomic_store_explicit(&g_WorkerStop, true, memory_order_release);

    if (atomic_load_explicit(&g_WorkerLive, memory_order_acquire)) {
        const u64 start_ms = cheatNowMs();

        /* Bounded wait: threadWaitForExit() has no timeout, and a worker stuck in a
         * dmnt IPC must not keep the shutdown (and the console's power menu) waiting
         * for ever.  The loop only sleeps between ticks, so this is generous. */
        while (!atomic_load_explicit(&g_WorkerDone, memory_order_acquire)) {
            if (cheatNowMs() - start_ms >= (u64)NXUS_CHEATSRV_EXIT_JOIN_MS) {
                joined = false;
                break;
            }
            svcSleepThread(10000000ull);
        }
        if (joined) {
            threadWaitForExit(&g_WorkerThread);
            threadClose(&g_WorkerThread);
            atomic_store_explicit(&g_WorkerLive, false, memory_order_release);
            NXUS_LOG("cheat: worker joined and closed");
        } else {
            /* Project rule: leak, never UAF.  The worker may still be reading the
             * program/journal, so neither those nor the Thread are released, and
             * g_Initialized stays set: a later Init must not create a second worker
             * that would execute on the same static stack and Thread object. */
            NXUS_LOG_ERROR("cheat: worker did not stop within %u ms - keeping its Thread and "
                           "state (a dmnt call may still be in flight)",
                           (unsigned)NXUS_CHEATSRV_EXIT_JOIN_MS);
            return;
        }
    }

    cheatLock();
    /* Give a stopped title its bytes back before their originals are forgotten.
     * Only for the target the program was uploaded for: writing journals that
     * belong to a previous process into whatever runs now would corrupt it. */
    if (g_ProgramLoaded && g_Journal.count != 0) {
        CheatTarget now;
        if (cheatTargetSample(&now) && cheatTargetSame(&g_Owner, &now)) {
            const CheatRestoreCount restored = cheatRestoreJournalLocked();
            NXUS_LOG("cheat: exit restored %u address(es) (%u failed)",
                     (unsigned)restored.restored, (unsigned)restored.failed);
        } else {
            NXUS_LOG("cheat: exit: target changed - %u patched address(es) left untouched "
                     "(writing them back would hit another process)",
                     (unsigned)g_Journal.count);
        }
    }
    (void)cheatDisableAllLocked();
    nxusCheatReset(&g_Program);
    nxusCheatJournalReset(&g_Journal);
    memset(&g_Owner, 0, sizeof(g_Owner));
    memset(g_ConsecutiveFailures, 0, sizeof(g_ConsecutiveFailures));
    g_ProgramLoaded = false;
    g_FaultCount = 0;
    cheatPublishStatus();
    cheatUnlock();

    g_Initialized = false;
    NXUS_LOG_DEBUG("cheat: service released");
}

bool nxusCheatSrvUpload(const void *wire, u32 length, NxusCheatUploadReply *reply) {
    NxusCheatUploadReply local_reply;
    NxusCheatProgramHeader header;
    CheatTarget now;
    u32 accepted_blocks;
    u32 accepted_insns;
    int rc;

    if (reply == NULL) reply = &local_reply;
    memset(reply, 0, sizeof(*reply));

    if (atomic_load_explicit(&g_Shutdown, memory_order_acquire)) {
        NXUS_LOG("cheat: upload refused - the service is shutting down");
        reply->rejected_reason = (u32)(-(s32)NXUS_CHEATVM_ERR_BAD_PROGRAM);
        return false;
    }
    if (wire == NULL || length < sizeof(NxusCheatProgramHeader)) {
        NXUS_LOG("cheat: upload refused - payload shorter than the program header");
        reply->rejected_reason = (u32)(-(s32)NXUS_CHEATVM_ERR_BAD_PROGRAM);
        return false;
    }
    memcpy(&header, wire, sizeof(header));

    if (!cheatTargetSample(&now) || now.pid == 0) {
        /* No process on the console: the client could not have resolved a single
         * address, so this program is meaningless (and running it later, once a
         * title starts, would patch an unrelated process). */
        NXUS_LOG("cheat: upload refused - the session has no target yet");
        reply->rejected_reason = (u32)(-(s32)NXUS_CHEATVM_ERR_BAD_PROGRAM);
        return false;
    }

    if (header.program_id != 0 && now.program_id != 0 && header.program_id != now.program_id) {
        NXUS_LOG("cheat: upload refused - program is for title %016llX but the target is "
                 "%016llX", (unsigned long long)header.program_id,
                 (unsigned long long)now.program_id);
        reply->rejected_reason = (u32)(-(s32)NXUS_CHEATVM_ERR_BAD_PROGRAM);
        return false;
    }

    cheatLock();
    /* Validate + install first: nxusCheatInstall() checks everything before it
     * writes a single byte, so a rejected upload leaves the running program AND its
     * journal intact. */
    rc = nxusCheatInstall(&g_Program, wire, length);
    if (rc != NXUS_CHEATVM_OK) {
        cheatUnlock();
        NXUS_LOG("cheat: upload rejected by the interpreter (rc=%d)", rc);
        reply->rejected_reason = (u32)(-rc);
        return false;
    }

    /* The block table now describes the new program, but the journal still
     * describes what the OLD one patched.  Undo it (the addresses belong to the
     * target we just verified) and start from an empty journal. */
    if (g_Journal.count != 0) {
        const CheatRestoreCount restored = cheatRestoreJournalLocked();
        NXUS_LOG("cheat: previous program: %u address(es) restored (%u failed)",
                 (unsigned)restored.restored, (unsigned)restored.failed);
    }
    nxusCheatJournalReset(&g_Journal);
    memset(g_ConsecutiveFailures, 0, sizeof(g_ConsecutiveFailures));
    g_Owner = now;
    g_Owner.valid = true;
    g_ProgramLoaded = true;
    g_FaultCount = 0;
    accepted_blocks = g_Program.header.block_count;
    accepted_insns = g_Program.header.insn_count;
    cheatPublishStatus();
    cheatUnlock();

    reply->accepted_blocks = accepted_blocks;
    reply->accepted_insns = accepted_insns;
    reply->rejected_reason = 0;
    NXUS_LOG("cheat: program installed (%u block(s), %u instruction(s), pid=%llu title=%016llX "
             "incarnation=%u)", (unsigned)accepted_blocks, (unsigned)accepted_insns,
             (unsigned long long)now.pid, (unsigned long long)now.program_id,
             (unsigned)now.incarnation);
    return true;
}

bool nxusCheatSrvSetEnabled(const NxusCheatEnable *req) {
    CheatTarget now;
    bool ok = false;

    if (req == NULL) return false;
    if (atomic_load_explicit(&g_Shutdown, memory_order_acquire)) return false;

    cheatLock();
    if (!g_ProgramLoaded) {
        NXUS_LOG("cheat: enable refused - no program is installed");
        goto done;
    }
    if (req->index >= g_Program.header.block_count) {
        NXUS_LOG("cheat: enable refused - block %u is outside the program (%u blocks)",
                 (unsigned)req->index, (unsigned)g_Program.header.block_count);
        goto done;
    }
    /* Turning something OFF is always allowed (it is the safe direction, and it lets
     * a client disarm a program whose target just went away).  Turning something ON
     * re-arms addresses, so it needs the target the program was uploaded for. */
    if (req->enabled != 0) {
        if (!g_Owner.valid) {
            NXUS_LOG("cheat: enable refused - the program was stopped for a target change "
                     "(re-upload it first)");
            goto done;
        }
        if (!cheatTargetSample(&now) || !cheatTargetSame(&g_Owner, &now)) {
            NXUS_LOG("cheat: enable refused - the target changed since the upload");
            goto done;
        }
        g_ConsecutiveFailures[req->index] = 0;
    }
    if (nxusCheatSetEnabled(&g_Program, req->index, req->enabled != 0) != NXUS_CHEATVM_OK) {
        NXUS_LOG("cheat: enable refused - the interpreter rejected block %u",
                 (unsigned)req->index);
        goto done;
    }
    cheatPublishStatus();
    ok = true;

done:
    cheatUnlock();
    return ok;
}

void nxusCheatSrvStatus(NxusCheatStatus *out) {
    NxusCheatStatus snapshot;
    bool clean = false;
    u32 attempt;

    if (out == NULL) return;

    for (attempt = 0; attempt < CHEATSRV_STATUS_RETRY; attempt++) {
        const u32 seq = atomic_load_explicit(&g_StatusSeq, memory_order_acquire);
        if ((seq & 1u) != 0) continue;              /* a publish is in flight */

        snapshot = g_Status;                        /* plain struct copy */

        /* Load/load barrier: without it the copy could be reordered past the
           re-check and a torn snapshot accepted. */
        atomic_thread_fence(memory_order_acquire);
        if (atomic_load_explicit(&g_StatusSeq, memory_order_acquire) != seq) continue;

        clean = true;
        break;
    }

    if (!clean) {
        /* Kept losing the race (a publish holds the odd marker for a few stores).
         * Report an empty snapshot rather than a torn one; the live fields below
         * still tell the client whether the worker is alive. */
        memset(&snapshot, 0, sizeof(snapshot));
        NXUS_LOG_DEBUG("cheat: status snapshot lost the race - reporting an empty one");
    }

    /* These two are sampled live on purpose: the mask changes with the controller,
     * and "is the worker running" is exactly what a client asks after an upload. */
    snapshot.running = atomic_load_explicit(&g_WorkerLive, memory_order_acquire) ? 1u : 0u;
    snapshot.keys_held = nxusHidHeldMask();
    *out = snapshot;
}

void nxusCheatSrvPanicOff(NxusCheatRestore *out) {
    NxusCheatRestore result;
    CheatRestoreCount restored;
    u32 stopped;

    memset(&result, 0, sizeof(result));

    cheatLock();
    stopped = cheatDisableAllLocked();
    restored = cheatRestoreJournalLocked();
    result.blocks_stopped = stopped;
    result.restored = restored.restored;
    result.failed = restored.failed;
    if (restored.failed == 0) nxusCheatJournalReset(&g_Journal);
    cheatPublishStatus();
    cheatUnlock();

    NXUS_LOG("cheat: panic off - %u block(s) stopped, %u/%u address(es) restored",
             (unsigned)stopped, (unsigned)restored.restored,
             (unsigned)(restored.restored + restored.failed));
    if (out != NULL) *out = result;
}

void nxusCheatSrvClear(void) {
    u32 patched;

    cheatLock();
    patched = g_Journal.count;
    (void)cheatDisableAllLocked();
    nxusCheatReset(&g_Program);
    nxusCheatJournalReset(&g_Journal);
    memset(&g_Owner, 0, sizeof(g_Owner));
    memset(g_ConsecutiveFailures, 0, sizeof(g_ConsecutiveFailures));
    g_ProgramLoaded = false;
    g_FaultCount = 0;
    cheatPublishStatus();
    cheatUnlock();

    NXUS_LOG("cheat: program dropped without writing back (%u patched address(es) - send "
             "CheatPanicOff first if they should be restored)", (unsigned)patched);
}
