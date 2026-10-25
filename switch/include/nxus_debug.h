/*
 * Nxus debug mode.
 *
 * dmnt:cht has no breakpoint API (verified against Atmosphère's service
 * definition), so watchpoints require Nxus to own the kernel debug session:
 *
 *   dmnt 65006 ForceCloseCheatProcess  ->  svcDebugActiveProcess
 *        -> debug event loop -> svcSetHardwareBreakPoint / thread contexts
 *   svcCloseHandle(debug)              ->  dmnt 65003 ForceOpenCheatProcess
 *
 * Because only one debugger may hold a process, cheat VM support is suspended
 * while debug mode is active.  That trade-off is deliberate and documented.
 */
#pragma once

#include <switch.h>

#include "nxus_protocol.h"

/* Hardware limit, and therefore the size of the break table: six instruction
   slots (0..5, one of which always holds the ContextID link source) plus four
   watchpoint slots (0x10..0x13) = ten.  The table has to be able to track every
   slot: with a smaller table the arm-then-store path could return success while
   the table had no entry for the slot that was just programmed, leaving an armed
   breakpoint that could not be listed or cleared. */
#define NXUS_DEBUG_MAX_BREAKS 10

void   nxusDebugInit(void);
/* Shutdown path only.  Never blocks: if another thread is already tearing the
 * session down, this logs and returns instead of waiting for it - the process is
 * exiting and the other thread owns every object the teardown touches (closing the
 * handle a second time would name a recycled handle).  Ordinary detach requests must
 * use nxusDebugDetach(). */
void   nxusDebugExit(void);

/* Take the process over with our own kernel debug session.
 *
 * Returns NXUS_ERR_BUSY (retryable) while another attach/detach hand-off owns the
 * session: attach never queues behind a detach, because the caller reports that BUSY
 * to the PC and a retry a moment later succeeds.  The hand-off is exclusive
 * (nxus_debug.c: g_TeardownOwner), so an attach can never publish g_Debug / the event
 * thread underneath a teardown that is still draining and closing the old handle. */
Result nxusDebugAttach(u64 pid);
/* Release the session: join the event thread, drain the counted debug operations,
 * close the debug handle and hand the process back to dmnt.  This is the one
 * teardown, and it runs EXACTLY ONCE even when several callers ask for it at the same
 * time (DebugDetach request, idle reap, Pause/Resume hand-back, exit collection):
 *
 *   - the caller that takes the hand-off claim performs the teardown;
 *   - a caller that finds the claim held waits for it - bounded by the same 2 s
 *     budget as the handle drain, with a short spin and a log line - and then either
 *     finds the session already released (no-op) or completes the release itself;
 *   - the shutdown path (nxusDebugExit()) does not wait at all, as documented there.
 *
 * Returns 0 once the session is released; a concurrent teardown is reported as
 * "released" rather than as an error, because that is what the caller asked for. */
Result nxusDebugDetach(void);
bool   nxusDebugIsAttached(void);
void   nxusDebugGetStatus(NxusDebugStatus *out);

/* ---- target architecture -------------------------------------------------
 * The debugee's own bitness, as announced by the kernel's CreateProcess event
 * (DebugEventInfo.flags bit 0).  It is collected during nxusDebugAttach() before
 * the event thread starts, so an immediate RegsGet / pointer scan already sees it,
 * and it is cleared on detach / exit so one target's architecture can never leak
 * into the next one.
 *
 * nxusDebugTargetIs64Bit() is false whenever the answer is unknown (no session, or
 * the CreateProcess event has not arrived); "unknown" is deliberately NOT the same
 * as "AArch32" - ask nxusDebugTargetIs64BitKnown() first and fall back to address
 * space evidence when it says false.  The pointer scan uses exactly this pair to
 * pick its load width: a 64-bit title can put its main module and heap below
 * 4 GiB, so the mapping ends alone are not trustworthy evidence. */
bool   nxusDebugTargetIs64Bit(void);
bool   nxusDebugTargetIs64BitKnown(void);

/* ---- detach safety -------------------------------------------------------
 * Every entry point below that hands the session handle to an svc*Debug* call is
 * counted by debugOpBegin()/debugOpEnd() in nxus_debug.c, and nxusDebugDetach()
 * waits for that counter to reach zero (a bounded two-stage drain (500 ms, then 1500 ms more; 2 s total)) before
 * it closes the handle.  That covers BreakSet/BreakClear (hardware arm through the
 * handle), Continue, Step, Break, ThreadList, RegsGet/RegsSet and the debug-mode
 * ContextID re-arm in nxusDebugConfigure(), as well as the memory accessors.
 *
 * A new operation that uses the session handle has to be wrapped the same way:
 * svcCloseHandle() frees the handle number for reuse, so an uncounted operation can
 * issue a syscall on a handle that now names an unrelated object.
 *
 * Deliberately outside the count: nxusDebugAttach()/nxusDebugDetach()/nxusDebugExit()
 * (they own the hand-off, and the detach is the one draining) and the pure state
 * readers - nxusDebugGetStatus(), nxusDebugGetBreaks(), nxusDebugGetHits(),
 * nxusDebugHitTotal(), nxusDebugGetConfig(), nxusDebugIsStopped() and friends -
 * which only read in-process state under g_Mutex or an atomic and never touch the
 * handle. */
/* Hand-off exclusivity: the count above keeps the HANDLE alive while an operation is
 * in flight; it does not serialise two teardowns.  That is the job of the hand-off
 * claim in nxus_debug.c (g_TeardownOwner): only its holder may join the event thread,
 * wipe the slots or call svcCloseHandle(), and attach refuses to start while it is
 * held.  Every entry point listed above may therefore run concurrently with a detach
 * (they are refused or drained), but only one detach/attach can be inside the teardown
 * at any moment.  nxusDebugIsHandoff() reports that hand-off window to readers outside
 * this module; it is a signal, not a lock. */
Result nxusDebugSetBreak(const NxusBreakRequest *request);
Result nxusDebugClearBreak(u32 slot);
u32    nxusDebugGetBreaks(NxusBreakEntry *out, u32 max_entries);

u32    nxusDebugGetHits(NxusBreakHit *out, u32 max_entries);
void   nxusDebugClearHits(void);
u32    nxusDebugHitTotal(void);

u32    nxusDebugGetThreads(NxusThreadEntry *out, u32 max_entries);
Result nxusDebugGetRegs(u64 thread_id, NxusThreadContext *out);
Result nxusDebugSetRegs(u64 thread_id, const NxusThreadContext *in);
Result nxusDebugContinueAll(void);

/* GDB-style stop management.  With auto_continue == 0 (the default) a breakpoint
   or watchpoint hit stops the target and leaves it stopped until the PC asks for
   DebugContinue or DebugStep.  While stopped the kernel keeps every thread of the
   process debug-suspended, so registers and memory stay readable. */
bool   nxusDebugIsStopped(void);
u64    nxusDebugStoppedThread(void);
/* Stores the mode and reports whether it is in effect.  Returns false only when
   auto-continue was enabled but a held target could not be released. */
bool   nxusDebugSetAutoContinue(u32 enabled);

/* Run a single instruction and stay stopped.  thread_id == 0 means "the thread the
   last stop was published for".  Always leaves the target stopped: the kernel's
   hardware single step is used when available, otherwise the target is resumed for
   a moment and stopped again with svcBreakDebugProcess (the fallback also re-sends
   NxusEvent_DebugStopped with the new PC). */
Result nxusDebugStep(u64 thread_id);
/* Stop the target without a breakpoint (svcBreakDebugProcess): the debug-session
   equivalent of Pause.  The stop is published like a hit. */
Result nxusDebugBreak(void);

/* True once the debugee has exited while the session was still attached.  The
   event thread cannot tear the session down itself (nxusDebugDetach() joins it),
   so it only raises this flag; nxusServerTick() collects the session and restores
   dmnt.  While set, nxusDebugAttach() refuses to start a second session. */
bool   nxusDebugExitedPending(void);
/* True while dmnt <-> own debug session ownership is being handed over. */
bool   nxusDebugIsHandoff(void);

void   nxusDebugConfigure(const NxusDebugConfig *config);
void   nxusDebugGetConfig(NxusDebugConfig *out);

/* While attached, memory access goes through the debug session instead of
   dmnt:cht (which is detached), so scanning and hex editing keep working. */
Result nxusDebugReadMemory(u64 address, void *buffer, u32 size);
Result nxusDebugWriteMemory(u64 address, const void *buffer, u32 size);
Result nxusDebugQueryMemory(u64 address, NxusMemoryInfo *out);

/* Compute the DBGBCR/DBGWCR control word for a request (exposed for tests). */
u64    nxusDebugBuildControl(u32 kind, u32 size, u64 address, u32 style);
u32    nxusDebugSlotForKind(u32 kind, u32 index);
