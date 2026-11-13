/*
 * Nxus console-side cheat service.
 *
 * core/nxus_cheatvm.h is the interpreter: it validates a LINKED program, runs one
 * block at a time and keeps the original bytes of everything it patches.  This
 * service is what makes it run on the console:
 *
 *   - it owns the one resident program, the scratch program of a patch-only
 *     upload, and the one journal (all STATIC, see the memory note below) and
 *     serialises the connection thread against the worker,
 *   - it drives a 16 ms worker that runs the enabled blocks, exactly like
 *     Atmosphère's cheat manager does inside the title.  A program that contains
 *     at least one LOOP block becomes resident; a PATCH-ONLY program is executed
 *     once during the upload and released immediately (see nxusCheatSrvUpload),
 *   - it refuses to run a program against a target it was not uploaded for: the
 *     upload stamps {pid, program_id, dmnt target incarnation} and every tick is
 *     compared against the live values.  A mismatch stops every block, writes the
 *     journal back and publishes NxusEvent_CheatFault(NXUS_CHEAT_FAULT_TARGET_GONE),
 *     so a title restart can never leave a patch behind in the next process,
 *   - it undoes everything it wrote on PanicOff (with no PC in the loop), and
 *     disables a block that failed NXUS_CHEATSRV_FAIL_LIMIT ticks in a row instead
 *     of hammering a dead address for ever,
 *   - it writes CODE (RX) only while the target is frozen: a block that patches
 *     code is wrapped in dmnt Pause (65004) / Resume (65005).  A half-written
 *     `bl` can be executed by a running thread, which is a guaranteed crash, so
 *     not freezing means not writing at all (see "Freezing" below).
 *
 * Freezing (RX writes)
 * --------------------
 * The interpreter cannot tell a .data store from a .text patch, so it passes
 * allow_rx == true for every store and this service decides:
 *
 *     nxusSessionCheckCodePatchRange()  read + (write OR execute)  accepted
 *     nxusSessionCheckRange(..., true)  read + write               plain data
 *
 * A range accepted by the code-patch policy but NOT writable is RX (.text is R-X
 * on the console).  A block is executed in two passes:
 *
 *   1. plan   - read-only; validates ranges, reads the current bytes and reports
 *               whether anything would actually change and whether any of it is RX,
 *   2. apply  - only when the plan found a differing write; the real journal and
 *               the real writer, inside Pause/Resume when the plan found RX.
 *
 * Consequences:
 *   - a loop block that applies the same patch every 16 ms writes (and freezes)
 *     only when the target value really differs, so the steady state costs reads
 *     only (this is what keeps the per-tick freeze off the hot path),
 *   - a failed Pause writes NOTHING: the block is disabled and
 *     NXUS_CHEAT_FAULT_CANNOT_FREEZE is published,
 *   - with a debug session attached dmnt is detached and 65004 cannot work, so RX
 *     blocks are skipped (reported once per attach) while data-only blocks keep
 *     running through the debug handle,
 *   - PanicOff and the journal write-backs of upload/exit are wrapped the same
 *     way; if the freeze fails the restore still runs (restoring is the safe
 *     direction) and the failure is reported and logged.
 *
 * Memory
 * ------
 * The sysmodule's inner heap is 8 MiB and already holds the scan chunk, the hit
 * list and up to two snapshot slots, so the program structures, the worker stack
 * and the journal DESCRIPTORS are .bss / static.  The two big variable-size arrays
 * are heap-allocated and sized to what is actually used:
 *
 *     sizeof(NxusCheatProgram)  ~5.4 KiB each (blocks + states; instructions live
 *                               on the heap, sized to the uploaded program)
 *     resident program          1 x NxusCheatProgram
 *     patch-upload scratch      1 x NxusCheatProgram (released after the upload)
 *     journal                   512 entries at Init (12 KiB), doubling on demand
 *                               up to NXUS_CHEATVM_MAX_JOURNAL = 16384 entries
 *                               (384 KiB) - see core/nxus_cheatvm.h
 *     plan-pass journal         same policy (its own array; never published)
 *     worker stack              8192 B
 *
 * The instruction arrays are allocated by nxusCheatInstall() and freed by
 * nxusCheatProgramRelease(); a patch-only upload allocates the scratch buffer,
 * runs the blocks once and releases it before returning, so repeated patch
 * uploads do not accumulate memory.  The journals are allocated by
 * nxusCheatJournalInit() in nxusCheatSrvInit() and freed by
 * nxusCheatJournalRelease() in nxusCheatSrvExit(); Clear/Reset only empty them.
 * The plan pass needs its own journal because the interpreter journals before it
 * calls write(); reusing the real journal would record ownership of bytes that
 * were never patched.  The static numbers are asserted in nxus_cheat_srv.c, so
 * lowering/raising a core cap cannot silently grow (or shrink) what the sysmodule
 * reserves.
 *
 * Threading
 * ---------
 * One worker thread, created by nxusCheatSrvInit() and joined by
 * nxusCheatSrvExit().  It is the only creator/destroyer of that Thread (no command
 * starts or stops it), so the shutdown needs no atomic Thread-slot claim like the
 * pointer scan; Exit still waits only a bounded time and - following the project
 * rule - leaks the Thread instead of closing/freeing state a worker might still
 * read.
 *
 * The program, its block states, the journal, the plan-pass journal and the
 * per-block failure counters are protected by one mutex (g_CheatLock).  Status does
 * NOT take that mutex: it reads a seqlock-published snapshot, so a status poll can
 * never be delayed by a tick that is inside a dmnt call.  That snapshot is
 * republished after every mutation (upload / enable / panic-off / clear / tick).
 * The freeze itself is strictly per tick / per restore: Pause and Resume are both
 * issued inside the same critical section, so a title is never left stopped across
 * ticks (and a slow client cannot inherit a freeze).
 *
 * Lock order: g_CheatLock is the innermost lock of this module.  It is held across
 * dmnt reads/writes, Pause/Resume and the event send, and no other Nxus lock is
 * taken while it is held by a caller that also holds a different Nxus lock first
 * (the dispatcher calls into this file without holding one).
 */
#pragma once

#include <switch.h>

#include "nxus_cheatvm.h"
#include "nxus_protocol.h"

/* Worker period.  Atmosphère runs the cheat VM once per frame; 16 ms is the same
 * "one frame" cadence at 60 Hz.  A tick that overruns its slot does NOT push the
 * next one back: the schedule advances by whole periods and the missed ticks are
 * dropped (see cheatSrvWorkerMain in nxus_cheat_srv.c), so the phase stays fixed. */
#define NXUS_CHEATSRV_PERIOD_NS 16000000ull

/* Consecutive failing ticks after which a block is disabled by the worker.
 * One failure is normal (a value that moves, a page that is momentarily
 * unreadable); three in a row without a single success means the block's address
 * is gone or the program is wrong, and continuing would just burn dmnt IPCs while
 * the cheat silently does nothing. */
#define NXUS_CHEATSRV_FAIL_LIMIT 3u

/* How long nxusCheatSrvExit() waits for the worker before it gives up on joining
 * it (the worker's longest step is bounded by NXUS_CHEATVM_STEP_LIMIT, but a single
 * dmnt IPC inside it is not). */
#define NXUS_CHEATSRV_EXIT_JOIN_MS 2000u

/* Journal capacity allocated by nxusCheatSrvInit().  The core doubles it on demand
 * up to NXUS_CHEATVM_MAX_JOURNAL (16384), so a normal cheat file pays 12 KiB while
 * one that rewrites thousands of addresses (the reported case: 858) still fits
 * without ever refusing a write. */
#define NXUS_CHEATSRV_JOURNAL_INITIAL 512u

/*
 * Boot the service: release any leftover program storage, reset the
 * program/journal/failure counters and start the 16 ms worker.  Idempotent for one
 * lifetime (a second call while initialised does nothing).  Call it AFTER
 * nxusServerInit() (the worker reports faults through nxusNetSendEvent, and main.c's
 * ordering owns that module) and BEFORE the network is expected to serve cheat
 * commands.
 */
void nxusCheatSrvInit(void);

/*
 * Terminal shutdown: ask the worker to stop, wait NXUS_CHEATSRV_EXIT_JOIN_MS for
 * it, join + close the Thread when it did, then release the program (including its
 * heap instruction array) and the journal.  While the target is still the one the
 * journal belongs to, it is written back first - a module stop must not leave a
 * title patched with bytes whose originals this service is about to forget.  That
 * restore covers the journal of a patch-only upload too (stamped with the target
 * even though no program is resident).
 *
 * Call it BEFORE nxusServerExit() (that call releases the session and raises the
 * terminal gate, and this one still wants dmnt).  Safe to call when never
 * initialised; a second call after a completed exit is a no-op.
 */
void nxusCheatSrvExit(void);

/*
 * Validate and install a wire program (NxusCheatProgramHeader + blocks + insns).
 *
 * The SERVER checks the payload length first (a short header, or a header whose
 * total_bytes disagrees with the payload, is NXUS_REASON_BAD_LENGTH).  This
 * function then
 *   - refuses a program whose header.program_id names another title than the one
 *     the session is on, and one uploaded with no target at all (the client cannot
 *     have resolved any address then),
 *   - runs the interpreter's validation (magic/version/sizes/branch targets) into
 *     a SCRATCH program, so a refused or out-of-memory upload never touches the
 *     installed one (NXUS_CHEATVM_ERR_NO_MEMORY is reported through
 *     rejected_reason like any other install error),
 *   - dispatches on the block table:
 *       * PATCH-ONLY (every block mode == 0): the program is executed once, right
 *         here, block by block - the same plan/apply pass the worker uses, with
 *         Pause/Resume around code writes.  What it writes stays in the journal
 *         (so a PC-less PanicOff can undo it), then the scratch program is
 *         RELEASED.  Nothing becomes resident: g_Program, its block states and
 *         `program_valid` are untouched, so a resident loop program keeps running
 *         and CheatStatus still describes it.  A patch block that fails is
 *         reported as a failed upload (rejected_reason = the interpreter error);
 *       * LOOP OR MIXED (at least one block mode == 1): the program becomes
 *         resident.  Whatever the previous program patched is written back first
 *         (inside the usual freeze), the old program's instruction array is
 *         released, and only then does the new program take its place.  A failure
 *         before that point leaves the old program installed and running.
 *   - stamps the runtime identity the worker will compare against every tick.
 *
 * *reply is always filled (accepted_blocks / accepted_insns on success,
 * rejected_reason otherwise).  `rejected_reason` encodes an interpreter error the
 * way NxusCheatUploadReply documents: the negative NXUS_CHEATVM_ERR_* as a positive
 * code (0 = accepted).  NXUS_CHEATVM_ERR_JOURNAL_FULL therefore arrives as 10.
 * Returns true only on success, and the caller maps false to
 * NXUS_ERR_BAD_STATE + NXUS_REASON_JOURNAL_FULL when the reason is journal-full,
 * NXUS_REASON_BAD_ARG otherwise.
 */
bool nxusCheatSrvUpload(const void *wire, u32 length, NxusCheatUploadReply *reply);

/*
 * Enable/disable one block.  Returns false when no program is installed or the
 * index is outside it, and - for an ENABLE only - when the target no longer matches
 * the upload or the program was already stopped for a target change; nothing is
 * touched then, because re-arming a program for a dead target must not patch
 * whatever runs now.  Disabling is always accepted (it is the safe direction, and it
 * lets a client disarm a program whose target just went away).  Enabling resets that
 * block's consecutive-failure counter, so a re-enable after a fault starts a fresh
 * NXUS_CHEATSRV_FAIL_LIMIT window.
 */
bool nxusCheatSrvSetEnabled(const NxusCheatEnable *req);

/*
 * Fill *out with the current snapshot (48 B).  Never blocks on the worker:
 * `program_valid`, `block_count`, `enabled_count`, `insn_count`, `tick_count`,
 * `journal_count`, `last_error`, `last_error_pc` and `fault_count` come from the
 * seqlock-published snapshot, while `running` and `keys_held` are read live.
 *
 * `program_valid`, `block_count` and `insn_count` describe the RESIDENT program
 * only: a patch-only upload runs synchronously and leaves no program behind, so it
 * never changes those three fields (its writes do show up in `journal_count`).
 *
 * `last_error` carries the interpreter's own (negative) NXUS_CHEATVM_ERR_* value of
 * the most recent failing block, 0 when the last tick had no failure - unlike
 * NxusCheatUploadReply.rejected_reason, which uses the positive encoding.
 */
void nxusCheatSrvStatus(NxusCheatStatus *out);

/*
 * Stop every block and write the journalled originals back.  *out reports how many
 * addresses were restored, how many could not be (the target is gone, or the range
 * is no longer writable) and how many blocks were still enabled.
 *
 * The restore is wrapped in Pause/Resume because it rewrites code too.  A failed
 * Pause does NOT cancel it (restoring is the safe direction), but it is counted in
 * `failed` (+1, the journal has no separate field for it and the wire structure is
 * fixed) and logged; the entries that could not be written back are kept so a
 * later, freezable PanicOff can retry them.  With a debug session attached dmnt is
 * detached and a freeze is not attempted; the restore goes through the debug
 * handle instead.
 *
 * The journal only keeps the addresses whose write-back FAILED (the interpreter
 * removes each entry it restored), so a retry does not rewrite what is already
 * correct and an exhausted journal frees up as it is restored.
 */
void nxusCheatSrvPanicOff(NxusCheatRestore *out);

/*
 * Drop the program and the journal WITHOUT writing anything to the target: the
 * NxusCmd_CheatClear contract ("drop the program (no writes)").  Patches that are
 * still applied stay applied and their originals are forgotten, so the log line
 * says so - a client that wants them undone sends CheatPanicOff first.  The
 * resident program's heap instruction array is released here.
 */
void nxusCheatSrvClear(void);
