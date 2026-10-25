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
void   nxusDebugExit(void);

Result nxusDebugAttach(u64 pid);
Result nxusDebugDetach(void);
bool   nxusDebugIsAttached(void);
void   nxusDebugGetStatus(NxusDebugStatus *out);

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
