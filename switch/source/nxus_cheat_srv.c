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
#include "nxus_heap.h"
#include "nxus_hid.h"
#include "nxus_log.h"
#include "nxus_net.h"
#include "nxus_server.h"
#include "nxus_session.h"

#include <stdalign.h>
#include <stdatomic.h>
#include <string.h>

/* ---- static footprint ---------------------------------------------------
 * The program structures are static (no stack copies): the sysmodule's 8 MiB
 * inner heap already holds the scan chunk, the hit list and up to two snapshot
 * slots, and NxusCheatProgram is ~5 KiB even though its instruction array is on
 * the heap.  g_Program is the resident (loop) program; g_PatchProgram is the
 * scratch program of a patch-only upload, which is installed, run once and
 * released inside nxusCheatSrvUpload() while g_CheatLock is held (see there).
 * The asserts below are deliberately UPPER bounds plus one total: raising a core
 * cap is fine as long as the reservation stays inside the documented budget, and
 * the build stops if it does not.
 *
 * Measured on the shipped caps: two program structs ~11 KiB, real journal 12296 B,
 * plan-pass journal 12296 B, stack 8192 B, total ~44 KiB.  The instruction arrays
 * themselves are heap-allocated to fit the uploaded program (see
 * core/nxus_cheatvm.h).  The plan pass needs its own journal because the
 * interpreter journals before calling write(); see CheatIoState.  The asserts
 * below pin the real footprint instead of a figure the types cannot meet, and
 * they are upper bounds so a future core cap that grows any structure fails the
 * build here rather than silently taking more of the sysmodule's memory. */
static NxusCheatProgram g_Program;
/* Scratch program for a PATCH-ONLY upload (every block mode == 0).  Uploads are
 * serialised by g_CheatLock, so one scratch slot is enough; it is released before
 * nxusCheatSrvUpload() returns and therefore never holds instructions between
 * calls. */
static NxusCheatProgram g_PatchProgram;
static NxusCheatJournal g_Journal;
/* Journal of the read-only plan pass (see CheatIoState / cheatSrvWorkerStep).  It
 * only exists so the interpreter's journal-full rule can run without polluting the
 * real journal with addresses that were never written; its contents are discarded
 * after every probe. */
static NxusCheatJournal g_ProbeJournal;
static alignas(0x1000) u8 g_WorkerStack[0x2000];

#define CHEATSRV_STATIC_MAX_BYTES (96u * 1024u)
NXUS_STATIC_ASSERT(sizeof(NxusCheatProgram) <= 56u * 1024u,
                   "NxusCheatProgram must stay inside the cheat service budget");
NXUS_STATIC_ASSERT(sizeof(NxusCheatJournal) <= 16u * 1024u,
                   "NxusCheatJournal must stay inside the cheat service budget");
NXUS_STATIC_ASSERT(2u * sizeof(NxusCheatProgram) + 2u * sizeof(NxusCheatJournal) +
                       sizeof(g_WorkerStack) <= CHEATSRV_STATIC_MAX_BYTES,
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
/* Debug-attach transition logs (worker thread only, reset by Init). */
static bool g_DebugSuspended;
static bool g_DebugRxNotified;

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
 * Both query the LIVE target (dmnt normally, the debug handle while a debug session
 * owns the process), so a freshly reloaded .text is judged as it is now rather than
 * against a scan-time snapshot.
 *
 * ---- RX (code) detection ------------------------------------------------
 *
 * "A store the code-patch policy accepts, on a mapping that is NOT writable" is a
 * code patch: .text is R-X on the console while .data is RW.  The verdict is cached
 * with the validated range (one query per mapping per tick), so a loop cheat that
 * stores to the same page 60 times a second does not multiply the IPC count.
 *
 * ---- planning pass ------------------------------------------------------
 *
 * Writing a `bl` (or any code patch) while the title runs is how a half-written
 * instruction gets executed.  A runnable block is therefore run TWICE:
 *
 *   1. a read-only PLAN pass with `probe = true`: every store is validated, the
 *      current bytes are read and compared, and the block records whether it would
 *      write anything and whether any of those writes land in RX,
 *   2. only when at least one write is actually needed is the block run again for
 *      real - inside Pause/Resume when it touches RX.
 *
 * This is what keeps a 16 ms loop free of freezes: after the first tick the target
 * already holds the requested value, the plan pass sees "nothing to write", and
 * neither a write nor a Pause is issued.
 *
 * The plan pass must not touch the real journal - it writes nothing, so journalling
 * would claim ownership of bytes that were never patched.  It gets its own static
 * journal instead (see g_ProbeJournal below).
 */
typedef struct {
    bool range_ok;
    u64  range_base;
    u64  range_size;
    bool range_code;       /* cached range is read-only/executable: code patch */
    u32  ranges_checked;
    u32  writes_ok;        /* accepted writes (a skipped no-op counts as restored) */
    u32  writes_failed;
    u32  writes_skipped;   /* the target already held the requested bytes */
    u32  writes_needed;    /* probe: differing writes the apply pass has to issue */
    bool probe;            /* read-only plan pass */
    bool plan_needs_write; /* probe: at least one write differs from memory */
    bool plan_needs_freeze;/* probe: at least one differing write targets RX */
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
        /* Same criterion as the write validation above, refined by the plain
         * writable check: RX code pages are not writable, data pages are. */
        state->range_code = allow_rx && !nxusSessionCheckRange(address, size, true);
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

/* Writer for the legitimate paths: dmnt owns the process normally, the debug
 * session owns it while a debugger is attached (RX blocks never reach this then -
 * they are refused before the write, see cheatSrvWorkerStep). */
static Result cheatSrvWriteTarget(u64 address, const void *data, u32 size) {
    if (nxusDebugIsAttached()) return nxusDebugWriteMemory(address, data, size);
    return nxusDmntWrite(address, data, size);
}

static int cheatSrvIoWrite(void *user, u64 address, const void *data, u32 size, bool allow_rx) {
    CheatIoState *state = (CheatIoState *)user;
    u8 current[8];

    if (state == NULL || data == NULL || size == 0 || size > sizeof(current)) return -1;
    if (!cheatIoRangeAllowed(state, address, size, allow_rx)) {
        state->writes_failed++;
        return -1;
    }

    /* Requirement: never write bytes the target already holds.  For an RX block
     * this is what makes the second and later ticks read-only: the plan pass
     * reports "nothing to do" and no Pause is issued at all.  A skipped restore
     * write still counts as restored, so PanicOff accounting stays exact. */
    if (nxusSessionReadMemory(address, current, size) == 0 &&
        memcmp(current, data, size) == 0) {
        state->writes_skipped++;
        state->writes_ok++;
        return 0;
    }

    if (state->probe) {
        /* Plan only: pretend the write succeeded so the rest of the block runs
         * exactly as it would for real, but touch nothing. */
        state->writes_needed++;
        state->plan_needs_write = true;
        if (state->range_code) state->plan_needs_freeze = true;
        state->writes_ok++;
        return 0;
    }

    if (R_FAILED(cheatSrvWriteTarget(address, data, size))) {
        state->writes_failed++;
        return -1;
    }
    state->writes_ok++;
    return 0;
}

static void cheatIoInit(CheatIoState *state, NxusCheatIo *io, bool probe) {
    memset(state, 0, sizeof(*state));
    state->probe = probe;
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

/* ---- freezing (dmnt Pause/Resume) --------------------------------------- */

/*
 * Pause the target through dmnt (65004 PauseCheatProcess) before a code write.
 * Returns true only when the process is genuinely stopped; the caller must then
 * call cheatSrvUnfreeze() on EVERY path (success, VM error, early return).
 *
 * While nxus_debug owns the process dmnt is detached and 65004 cannot work.  The
 * caller refuses the RX block instead of writing unfrozen code (see
 * cheatSrvWorkerStep); this helper reports "no freeze" rather than attempting a
 * dmnt call that would be answered by a closed service.
 */
static bool cheatSrvFreeze(const char *why) {
    const u64 start_ns = cheatNowNs();
    Result rc;

    if (nxusDebugIsAttached()) {
        NXUS_LOG_DEBUG("cheat: %s: a debug session owns the process - no dmnt freeze",
                       (why != NULL) ? why : "freeze");
        return false;
    }
    rc = nxusDmntPause();
    if (R_FAILED(rc)) {
        NXUS_LOG("cheat: %s: PauseCheatProcess failed (rc=0x%08X) - refusing the code write",
                 (why != NULL) ? why : "freeze", (unsigned)rc);
        return false;
    }
    /* No status field can carry this (NxusCheatStatus is a fixed 48-byte wire
     * structure), so the freeze duration is logged instead. */
    NXUS_LOG_DEBUG("cheat: %s: target frozen after %llu us",
                   (why != NULL) ? why : "freeze",
                   (unsigned long long)((cheatNowNs() - start_ns) / 1000ull));
    return true;
}

/* Always paired with cheatSrvFreeze() == true.  A failed Resume is logged but not
 * retried here: the caller is already at its single exit point and a retry would
 * itself have to guess whether the process is running. */
static void cheatSrvUnfreeze(const char *why) {
    Result rc = nxusDmntResume();
    if (R_FAILED(rc)) {
        NXUS_LOG_ERROR("cheat: %s: ResumeCheatProcess failed (rc=0x%08X) - the target may "
                       "still be stopped", (why != NULL) ? why : "freeze", (unsigned)rc);
    }
}

/* Restore the journalled originals through the adapter and report what happened.
 * The counters live in the adapter, so a partial failure is reported exactly
 * instead of being inferred from the interpreter's all-or-nothing return value.
 *
 * `freeze` wraps the restore in Pause/Resume: writing the originals back is also a
 * code write, and a half-restored instruction is just as executable as a
 * half-written patch.  The restore runs even when the freeze failed (restoring is
 * the safe direction); `freeze_failed` records that it did so unfrozen. */
typedef struct {
    u32  restored;
    u32  failed;
    bool freeze_failed;   /* freeze was attempted for this restore and failed */
} CheatRestoreCount;

static CheatRestoreCount cheatRestoreJournalLocked(bool freeze) {
    CheatRestoreCount count;
    CheatIoState state;
    NxusCheatIo io;
    bool paused = false;

    memset(&count, 0, sizeof(count));
    if (freeze && g_Journal.count != 0) {
        paused = cheatSrvFreeze("journal restore");
        count.freeze_failed = !paused && !nxusDebugIsAttached();
    }
    cheatIoInit(&state, &io, false);
    if (nxusCheatJournalRestore(&g_Journal, &io, true) < 0) {
        NXUS_LOG_DEBUG("cheat: journal restore reported a failed address");
    }
    count.restored = state.writes_ok;
    count.failed = state.writes_failed;
    if (count.freeze_failed) {
        NXUS_LOG("cheat: journal restore: could not freeze the target - %u/%u address(es) "
                 "written back without the freeze",
                 (unsigned)count.restored, (unsigned)(count.restored + count.failed));
    }
    /* Single exit point: the target is resumed on success, on a partial restore
     * and on a refused range, because the freeze must never outlive one restore. */
    if (paused) cheatSrvUnfreeze("journal restore");
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

/* ---- per-block execution ------------------------------------------------
 *
 * nxusCheatTick() runs every block in one go, which cannot express a
 * per-block Pause/Resume.  The worker therefore drives one block at a time with
 * the interpreter's public nxusCheatRunBlock() and mirrors the tick bookkeeping
 * (patch blocks once per enable, exactly one execs/tick_count step per tick).
 *
 * A block is executed in two passes:
 *   probe  - read-only; reports whether anything would be written and whether
 *            any of it targets code,
 *   apply  - only when the probe found a differing write; the real journal and
 *            the real writer, inside Pause/Resume when the target is code.
 */

/* Read-only plan pass.  Does not touch the real journal and writes nothing.
 * `state`/`io` are owned by the caller so the apply pass below can reuse the
 * validated-range cache (one live mapping query per range per tick, not two).
 * `program` is g_Program for the worker, or g_PatchProgram for a patch-only
 * upload's one-shot run. */
static int cheatSrvProbeBlockLocked(NxusCheatProgram *program, u32 index, u64 keys,
                                    CheatIoState *state, NxusCheatIo *io,
                                    bool *needs_write, bool *needs_freeze) {
    int rc;

    nxusCheatJournalReset(&g_ProbeJournal);
    cheatIoInit(state, io, true);
    rc = nxusCheatRunBlock(program, index, io, keys, &g_ProbeJournal);
    if (needs_write != NULL) *needs_write = state->plan_needs_write;
    if (needs_freeze != NULL) *needs_freeze = state->plan_needs_freeze;
    return rc;
}

/* Real pass: writes through the real journal, skipping bytes the target already
 * holds (the adapter does that read/compare itself).  Reuses the plan pass's
 * range cache; only the mode changes. */
static int cheatSrvApplyBlockLocked(NxusCheatProgram *program, u32 index, u64 keys,
                                    CheatIoState *state, NxusCheatIo *io) {
    state->probe = false;
    return nxusCheatRunBlock(program, index, io, keys, &g_Journal);
}

static void cheatBlockSucceededLocked(u32 index) {
    NxusCheatBlockState *state = &g_Program.state[index];

    state->execs++;
    state->last_error = 0;
    state->error_pc = 0;
    if (g_Program.blocks[index].mode == 0) state->ran_once = true;
    g_ConsecutiveFailures[index] = 0;
}

/* Same failure policy the tick path had: a transient failure is retried,
 * NXUS_CHEATSRV_FAIL_LIMIT consecutive ones disable the block, and a full journal
 * disables it immediately (waiting would only repeat the refusal).
 *
 * nxusCheatRunBlock() does not expose the failing instruction index (only the
 * internal cheatRunBlock() of core does), so error_pc is reported as 0 rather
 * than guessed. */
static void cheatBlockFailedLocked(u32 index, int rc, NxusCheatFault *fault,
                                   bool *have_fault) {
    NxusCheatBlockState *state = &g_Program.state[index];

    state->execs++;
    state->last_error = (u32)rc;
    state->error_pc = 0;

    if (rc == NXUS_CHEATVM_ERR_WRITE && g_Journal.count >= g_Journal.capacity) {
        if (fault != NULL && have_fault != NULL && !*have_fault) {
            memset(fault, 0, sizeof(*fault));
            fault->reason = NXUS_CHEAT_FAULT_JOURNAL_FULL;
            fault->block = index;
            fault->pc = 0;
            *have_fault = true;
        }
        cheatDisableBlockLocked(index);
        NXUS_LOG("cheat: block %u: journal full - block disabled", (unsigned)index);
        return;
    }

    if (g_ConsecutiveFailures[index] < 0xFFu) g_ConsecutiveFailures[index]++;
    if (g_ConsecutiveFailures[index] < NXUS_CHEATSRV_FAIL_LIMIT) return;

    if (fault != NULL && have_fault != NULL && !*have_fault) {
        memset(fault, 0, sizeof(*fault));
        fault->reason = (u32)(-(s32)rc);   /* the documented positive code */
        fault->block = index;
        fault->pc = 0;
        *have_fault = true;
    }
    cheatDisableBlockLocked(index);
    NXUS_LOG("cheat: block %u failed %u tick(s) in a row (err=%d) - block disabled",
             (unsigned)index, (unsigned)NXUS_CHEATSRV_FAIL_LIMIT, rc);
}

/* One-shot execution of a PATCH-ONLY upload (every block mode == 0).
 *
 * Called from nxusCheatSrvUpload() with g_CheatLock held, right after the program
 * was installed into g_PatchProgram, and before that program is released.  It
 * reuses the worker's plan/apply machinery - the same validated-range cache, the
 * same "never write bytes the target already holds" rule and the same
 * Pause/Resume around RX stores - but runs each enabled block exactly once and
 * writes through the real journal, so a PC-less PanicOff can undo those writes.
 *
 * There is no retry window here (a patch block used to get NXUS_CHEATSRV_FAIL_LIMIT
 * ticks before it was disabled): the upload is synchronous, so a failure is
 * reported to the client as the interpreter's error instead of being retried in
 * the background.  Writes that already happened stay journalled even on the error
 * path - they are real patches and must remain reversible.
 *
 * Returns NXUS_CHEATVM_OK, or the first interpreter error / a refusal
 * (NXUS_CHEATVM_ERR_WRITE) when an RX block cannot be frozen. */
static int cheatSrvRunPatchProgramLocked(NxusCheatProgram *program) {
    const u64 keys = nxusHidHeldMask();
    const bool debug_attached = nxusDebugIsAttached();
    u32 blocks;
    u32 i;

    blocks = program->header.block_count;
    if (blocks > NXUS_CHEATVM_MAX_BLOCKS) blocks = NXUS_CHEATVM_MAX_BLOCKS;

    for (i = 0; i < blocks; i++) {
        CheatIoState io_state;
        NxusCheatIo io;
        bool needs_write = false;
        bool needs_freeze = false;
        bool paused = false;
        int rc;

        /* The upload-time enable flag is honoured: a disabled patch block stays a
         * no-op, exactly as it would if the program had become resident. */
        if (!program->state[i].enabled) continue;

        rc = cheatSrvProbeBlockLocked(program, i, keys, &io_state, &io, &needs_write,
                                      &needs_freeze);
        if (rc != NXUS_CHEATVM_OK) {
            NXUS_LOG("cheat: patch upload: block %u failed in the plan pass (err=%d) - "
                     "the program is not executed further", (unsigned)i, rc);
            return rc;
        }
        if (!needs_write) continue;   /* the target already holds every value */

        if (needs_freeze && debug_attached) {
            /* dmnt is detached, so 65004 cannot stop the title: writing half an
             * instruction now is the crash this service exists to prevent. */
            NXUS_LOG("cheat: patch upload: block %u patches code but a debug session "
                     "owns the process - refused (no dmnt freeze)", (unsigned)i);
            return NXUS_CHEATVM_ERR_WRITE;
        }
        if (needs_freeze) {
            paused = cheatSrvFreeze("patch upload");
            if (!paused) {
                NXUS_LOG("cheat: patch upload: block %u patches code but the target "
                         "could not be frozen - refused without writing", (unsigned)i);
                return NXUS_CHEATVM_ERR_WRITE;
            }
        }

        rc = cheatSrvApplyBlockLocked(program, i, keys, &io_state, &io);
        /* Single exit point: the freeze never outlives this block. */
        if (paused) cheatSrvUnfreeze("patch upload");
        if (rc != NXUS_CHEATVM_OK) {
            NXUS_LOG("cheat: patch upload: block %u failed while writing (err=%d) - "
                     "what was written stays journalled", (unsigned)i, rc);
            return rc;
        }
    }
    return NXUS_CHEATVM_OK;
}

/* One tick: verify the target, run every enabled block through the interpreter,
 * disarm blocks that keep failing.  Exposed to the host test through the file
 * include (it is static on purpose: only the worker may call it in production). */
static void cheatSrvWorkerStep(void) {
    CheatTarget now;
    NxusCheatFault fault;
    bool have_fault = false;
    bool debug_attached;
    u32 blocks;
    u32 i;

    /* While a debug session owns the process dmnt is closed, so 65004 cannot
     * freeze anything.  Data-only blocks may keep running (they use the debug
     * handle), but a block that patches code is REFUSED: writing half an
     * instruction while the title runs is exactly the crash this guards. */
    debug_attached = nxusDebugIsAttached();
    if (debug_attached) {
        if (!g_DebugSuspended) {
            g_DebugSuspended = true;
            g_DebugRxNotified = false;
            NXUS_LOG("cheat: debug session holds the process - RX blocks are suspended "
                     "(data-only blocks keep running)");
        }
    } else if (g_DebugSuspended) {
        g_DebugSuspended = false;
        g_DebugRxNotified = false;
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
        /* No freeze here: the identity just changed, so a Pause would stop a
         * process these journalled addresses no longer belong to.  The restore is
         * still attempted (writing through the live mapping check refuses any
         * address that moved). */
        const CheatRestoreCount restored = cheatRestoreJournalLocked(false);

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

    /* The HID mask is sampled EVERY tick (the worker owns that read; a user presses
     * the combo long after the upload).  Each runnable block - an enabled loop
     * block every tick, an enabled patch block once - runs through the plan pass
     * first, and only a block that really has something to write is applied. */
    {
        const u64 keys = nxusHidHeldMask();

        for (i = 0; i < blocks; i++) {
            NxusCheatBlockState *state = &g_Program.state[i];
            CheatIoState io_state;
            NxusCheatIo io;
            bool needs_write = false;
            bool needs_freeze = false;
            bool paused = false;
            int rc;

            if (!state->enabled) continue;
            if (g_Program.blocks[i].mode == 0 && state->ran_once) continue;

            rc = cheatSrvProbeBlockLocked(&g_Program, i, keys, &io_state, &io,
                                          &needs_write, &needs_freeze);
            if (rc != NXUS_CHEATVM_OK) {
                /* The plan pass already validates ranges and journals, so this is
                 * the same failure the real pass would report - and it happened
                 * without a single write. */
                cheatBlockFailedLocked(i, rc, &fault, &have_fault);
                continue;
            }
            if (!needs_write) {
                /* Everything the block would write is already there: no write and,
                 * crucially, no Pause.  This is the steady state of a 16 ms loop. */
                cheatBlockSucceededLocked(i);
                continue;
            }

            if (needs_freeze && debug_attached) {
                /* dmnt is detached: no 65004, so no safe code write.  Skip the
                 * block (it stays enabled and resumes after the debug detach) and
                 * tell the PC once per attach instead of hammering the link. */
                if (!g_DebugRxNotified) {
                    g_DebugRxNotified = true;
                    if (!have_fault) {
                        memset(&fault, 0, sizeof(fault));
                        fault.reason = NXUS_CHEAT_FAULT_CANNOT_FREEZE;
                        fault.block = i;
                        fault.pc = 0;
                        fault.restored = 0;
                        have_fault = true;
                    }
                    NXUS_LOG("cheat: block %u patches code but a debug session owns the "
                             "process - RX block not executed (no dmnt freeze)", (unsigned)i);
                }
                continue;
            }

            if (needs_freeze) {
                paused = cheatSrvFreeze("cheat RX block");
                if (!paused) {
                    /* The exact accident this guards: write a code patch only while
                     * the title is stopped.  No freeze -> no write at all. */
                    if (!have_fault) {
                        memset(&fault, 0, sizeof(fault));
                        fault.reason = NXUS_CHEAT_FAULT_CANNOT_FREEZE;
                        fault.block = i;
                        fault.pc = 0;
                        fault.restored = 0;
                        have_fault = true;
                    }
                    cheatDisableBlockLocked(i);
                    NXUS_LOG("cheat: block %u patches code but the target could not be "
                             "frozen - block disabled without writing", (unsigned)i);
                    continue;
                }
            }

            rc = cheatSrvApplyBlockLocked(&g_Program, i, keys, &io_state, &io);
            /* Single exit point: resume on success, on a VM error and on a failed
             * write alike.  The freeze never outlives this block. */
            if (paused) cheatSrvUnfreeze("cheat RX block");

            if (rc == NXUS_CHEATVM_OK) {
                cheatBlockSucceededLocked(i);
            } else {
                cheatBlockFailedLocked(i, rc, &fault, &have_fault);
            }
        }
        g_Program.tick_count++;
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
     * (Init runs on the boot path, before the listener serves cheat commands).
     * Release (not just reset) frees the instruction array in case a previous
     * lifetime left one behind; both calls are no-ops on static-zero storage. */
    nxusCheatProgramRelease(&g_Program);
    nxusCheatProgramRelease(&g_PatchProgram);
    nxusCheatJournalReset(&g_Journal);
    nxusCheatJournalReset(&g_ProbeJournal);
    memset(&g_Owner, 0, sizeof(g_Owner));
    memset(g_ConsecutiveFailures, 0, sizeof(g_ConsecutiveFailures));
    g_ProgramLoaded = false;
    g_FaultCount = 0;
    g_MissedTicks = 0;
    g_DebugSuspended = false;
    g_DebugRxNotified = false;
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
     * Gated on the journal's own target stamp (g_Owner), not on a resident
     * program: a PATCH-ONLY upload keeps no program but does fill the journal, and
     * those bytes must still be reversible on the way out.  Writing journals that
     * belong to a previous process into whatever runs now would corrupt it, hence
     * the identity comparison. */
    if (g_Owner.valid && g_Journal.count != 0) {
        CheatTarget now;
        if (cheatTargetSample(&now) && cheatTargetSame(&g_Owner, &now)) {
            const CheatRestoreCount restored = cheatRestoreJournalLocked(true);
            NXUS_LOG("cheat: exit restored %u address(es) (%u failed)",
                     (unsigned)restored.restored, (unsigned)restored.failed);
        } else {
            NXUS_LOG("cheat: exit: target changed - %u patched address(es) left untouched "
                     "(writing them back would hit another process)",
                     (unsigned)g_Journal.count);
        }
    }
    (void)cheatDisableAllLocked();
    nxusCheatProgramRelease(&g_Program);
    nxusCheatProgramRelease(&g_PatchProgram);
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

/* One line per refused upload with every value needed to tell a malformed program
 * from a wrong title: the interpreter rc (or the negative NXUS_CHEATVM_ERROR the
 * reply carries), the block/instruction counts the client sent, the program id it
 * was built for and the identity the console is actually running.  The wire reply
 * is unchanged (BAD_STATE + reason=9); this is the console-side explanation that
 * used to be missing when a Wi-Fi switch/target change made an upload fail.
 *
 * The heap line is the second half of the diagnostic: a reconnect storm is exactly
 * when "upload failed" and "the module is short of heap" have to be told apart. */
static void cheatLogUploadRejected(int rc, const NxusCheatProgramHeader *header,
                                   const CheatTarget *target, const char *why) {
    NXUS_LOG("cheat: upload rejected rc=%d blocks=%u insns=%u program_id=%016llX "
             "target_pid=%llu target_program_id=%016llX incarnation=%u (%s)",
             rc,
             (header != NULL) ? (unsigned)header->block_count : 0u,
             (header != NULL) ? (unsigned)header->insn_count : 0u,
             (unsigned long long)((header != NULL) ? header->program_id : 0ull),
             (unsigned long long)((target != NULL && target->valid) ? target->pid : 0ull),
             (unsigned long long)((target != NULL && target->valid) ? target->program_id : 0ull),
             (unsigned)((target != NULL && target->valid) ? target->incarnation : 0u),
             (why != NULL) ? why : "?");
    nxusHeapLog("cheat upload rejected");
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
    /* The rejection line reports the sampled identity even when the sample failed
       (`valid` stays false), so never leave the struct uninitialised. */
    memset(&now, 0, sizeof(now));

    if (atomic_load_explicit(&g_Shutdown, memory_order_acquire)) {
        NXUS_LOG("cheat: upload refused - the service is shutting down");
        cheatLogUploadRejected(NXUS_CHEATVM_ERR_BAD_PROGRAM, NULL, NULL,
                               (wire == NULL) ? "no payload" : "service shutting down");
        reply->rejected_reason = (u32)(-(s32)NXUS_CHEATVM_ERR_BAD_PROGRAM);
        return false;
    }
    if (wire == NULL || length < sizeof(NxusCheatProgramHeader)) {
        NXUS_LOG("cheat: upload refused - payload shorter than the program header");
        cheatLogUploadRejected(NXUS_CHEATVM_ERR_BAD_PROGRAM, NULL, NULL,
                               "payload shorter than the program header");
        reply->rejected_reason = (u32)(-(s32)NXUS_CHEATVM_ERR_BAD_PROGRAM);
        return false;
    }
    memcpy(&header, wire, sizeof(header));

    if (!cheatTargetSample(&now) || now.pid == 0) {
        /* No process on the console: the client could not have resolved a single
         * address, so this program is meaningless (and running it later, once a
         * title starts, would patch an unrelated process). */
        NXUS_LOG("cheat: upload refused - the session has no target yet");
        cheatLogUploadRejected(NXUS_CHEATVM_ERR_BAD_PROGRAM, &header, &now,
                               "the session has no target");
        reply->rejected_reason = (u32)(-(s32)NXUS_CHEATVM_ERR_BAD_PROGRAM);
        return false;
    }

    if (header.program_id != 0 && now.program_id != 0 && header.program_id != now.program_id) {
        NXUS_LOG("cheat: upload refused - program is for title %016llX but the target is "
                 "%016llX", (unsigned long long)header.program_id,
                 (unsigned long long)now.program_id);
        cheatLogUploadRejected(NXUS_CHEATVM_ERR_BAD_PROGRAM, &header, &now,
                               "program id does not match the running title");
        reply->rejected_reason = (u32)(-(s32)NXUS_CHEATVM_ERR_BAD_PROGRAM);
        return false;
    }

    cheatLock();

    /* Re-check under the lock: Exit raises g_Shutdown before it takes the lock, so
     * this closes the window between the check above and this section. */
    if (atomic_load_explicit(&g_Shutdown, memory_order_acquire)) {
        cheatUnlock();
        NXUS_LOG("cheat: upload refused - the service is shutting down");
        cheatLogUploadRejected(NXUS_CHEATVM_ERR_BAD_PROGRAM, &header, &now,
                               "service shutting down (under the lock)");
        reply->rejected_reason = (u32)(-(s32)NXUS_CHEATVM_ERR_BAD_PROGRAM);
        return false;
    }

    /* Validate and ALLOCATE into the scratch program first, never into g_Program:
     *   - a patch-only upload must not displace the resident program, and
     *   - a resident replacement must keep the old program when the new one is
     *     refused or runs out of memory (nxusCheatInstall checks everything and
     *     allocates before it touches its target struct).
     * Release is idempotent, so reusing the scratch slot from a previous upload is
     * safe even if that one failed. */
    nxusCheatProgramRelease(&g_PatchProgram);
    rc = nxusCheatInstall(&g_PatchProgram, wire, length);
    if (rc != NXUS_CHEATVM_OK) {
        nxusCheatProgramRelease(&g_PatchProgram);
        cheatUnlock();
        NXUS_LOG("cheat: upload rejected by the interpreter (rc=%d) - the installed "
                 "program was left untouched", rc);
        cheatLogUploadRejected(rc, &header, &now, "interpreter validation");
        reply->rejected_reason = (u32)(-rc);
        return false;
    }

    /* The upload mode is decided by the block table: one loop block makes the
     * program resident, otherwise it is a one-shot patch program. */
    {
        bool has_loop = false;
        u32 i;

        for (i = 0; i < g_PatchProgram.header.block_count; i++) {
            if (g_PatchProgram.blocks[i].mode != 0) {
                has_loop = true;
                break;
            }
        }

        if (!has_loop) {
            /* ---- patch-only: run every block exactly once, keep nothing ---------
             * The program is executed through the same plan/apply pass the worker
             * uses (freeze around RX stores, skip bytes already in memory) and the
             * writes stay journalled in g_Journal, which is the console-side truth
             * for PanicOff.  g_Program, g_ProgramLoaded and the upload target stamp
             * are NOT touched, so the resident program (if any) keeps running. */
            const int run_rc = cheatSrvRunPatchProgramLocked(&g_PatchProgram);
            u32 journalled;

            accepted_blocks = g_PatchProgram.header.block_count;
            accepted_insns = g_PatchProgram.header.insn_count;
            nxusCheatProgramRelease(&g_PatchProgram);

            /* The journal now belongs to this target: Exit uses g_Owner to decide
             * whether writing it back is safe.  A resident program keeps its own
             * stamp - this upload was verified against the same target above. */
            if (!g_ProgramLoaded) {
                g_Owner = now;
                g_Owner.valid = true;
            }
            journalled = g_Journal.count;
            cheatPublishStatus();
            cheatUnlock();

            if (run_rc != NXUS_CHEATVM_OK) {
                NXUS_LOG("cheat: patch program failed while running (err=%d) - %u block(s) "
                         "were not applied, %u address(es) stay journalled for PanicOff",
                         run_rc, (unsigned)accepted_blocks, (unsigned)journalled);
                cheatLogUploadRejected(run_rc, &header, &now,
                                       "patch program failed while running");
                reply->rejected_reason = (u32)(-run_rc);
                return false;
            }

            reply->accepted_blocks = accepted_blocks;
            reply->accepted_insns = accepted_insns;
            reply->rejected_reason = 0;
            NXUS_LOG("cheat: patch program executed once and released (%u block(s), %u "
                     "instruction(s), %u journalled address(es); no resident program)",
                     (unsigned)accepted_blocks, (unsigned)accepted_insns,
                     (unsigned)journalled);
            return true;
        }
    }

    /* ---- resident program (contains at least one loop block) -----------------
     * The new program is already validated and allocated, so anything that could
     * fail has failed above and the old program is still intact.  What remains is
     * the swap: undo what the OLD program patched (with the freeze), release its
     * instruction array and only then make the new program resident. */
    if (g_Journal.count != 0) {
        const CheatRestoreCount restored = cheatRestoreJournalLocked(true);
        NXUS_LOG("cheat: previous program: %u address(es) restored (%u failed)",
                 (unsigned)restored.restored, (unsigned)restored.failed);
    }
    nxusCheatJournalReset(&g_Journal);
    nxusCheatProgramRelease(&g_Program);
    g_Program = g_PatchProgram;
    nxusCheatProgramInit(&g_PatchProgram);   /* the pointer moved; do not free it twice */

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
    /* PanicOff is the "no PC in the loop" recovery: it writes code originals back,
     * so it runs inside Pause/Resume.  A failed freeze does NOT cancel the restore
     * (restoring is the safe direction), but it is reported as a failure so a
     * client can tell the repair happened unfrozen. */
    restored = cheatRestoreJournalLocked(true);
    result.blocks_stopped = stopped;
    result.restored = restored.restored;
    result.failed = restored.failed + (restored.freeze_failed ? 1u : 0u);
    /* Keep the journal when an address failed OR the restore ran unfrozen, so a
     * later (freezable) PanicOff can retry the whole write-back. */
    if (restored.failed == 0 && !restored.freeze_failed) nxusCheatJournalReset(&g_Journal);
    cheatPublishStatus();
    cheatUnlock();

    if (restored.freeze_failed) {
        NXUS_LOG("cheat: panic off - %u block(s) stopped, %u address(es) restored WITHOUT a "
                 "freeze (reported as failed)", (unsigned)stopped,
                 (unsigned)restored.restored);
    } else {
        NXUS_LOG("cheat: panic off - %u block(s) stopped, %u/%u address(es) restored",
                 (unsigned)stopped, (unsigned)restored.restored,
                 (unsigned)(restored.restored + restored.failed));
    }
    if (out != NULL) *out = result;
}

void nxusCheatSrvClear(void) {
    u32 patched;

    cheatLock();
    patched = g_Journal.count;
    (void)cheatDisableAllLocked();
    /* Release, not just reset: Clear drops the program for good (no re-install on
     * the same buffer), so its heap instruction array must go with it. */
    nxusCheatProgramRelease(&g_Program);
    nxusCheatProgramRelease(&g_PatchProgram);
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
