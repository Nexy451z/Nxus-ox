/* Nxus command dispatcher. */
#pragma once

#include "nxus_protocol.h"

#ifdef __SWITCH__
#include <switch.h>
#else
/* The pure command-classification helpers at the bottom of this header are
   compiled by the host test (tests/test_server_logic.c), which has no libnx.
   libnx's Result is a u32 and nothing else here needs the console's <switch.h>;
   redeclaring an identical typedef is legal C11, so a test that also includes the
   libnx stub header keeps compiling. */
typedef u32 Result;
#endif

#define NXUS_MAX_HITS_PER_BATCH 8192u
#define NXUS_DEBUG_SERVER_MAX_BREAKS  8u
#define NXUS_DEBUG_SERVER_MAX_HITS    32u
#define NXUS_DEBUG_SERVER_MAX_THREADS 32u

/* Pointer-scan acknowledgement.

   PtrScanBegin does not walk the chain graph itself any more: the walk runs on a
   worker thread (nxus_server.c: ptrScanThread) so the connection thread keeps
   polling the listen socket and reading heartbeats for the whole 90 s budget.
   The command therefore answers with this Result instead of the chain list, and
   the client polls PtrScanGet until it succeeds (chains) or reports the walk's
   failure (anything but BUSY / this code).

   It travels as the s32 Result of an ordinary error reply, so a client that
   predates this change prints "PtrScanBegin failed: result=0x........" - a
   visible refusal instead of a silent "0 chains found".  Desc 8 is the next free
   Nxus code after core/nxus_protocol.h's 1..7.  The PC clients mirror the value
   (pc/Nxus.Cli/src/client.rs, pc/nxus/client.py): core/nxus_protocol.h stays the
   single source of truth for the shared wire format, and this is a server-side
   status, not a protocol element. */
#define NXUS_ERR_PTRSCAN_STARTED 8u
#define NXUS_RESULT_PTRSCAN_STARTED ((Result)NXUS_MAKE_RESULT(NXUS_ERR_PTRSCAN_STARTED))

/* Boot the dispatcher.  Also re-arms the terminal gate (see nxusServerExit), so a
   second Init in the same process - the test harness boots the server, exits it and
   boots it again - starts with commands and ticks served again instead of inheriting
   the previous round's refusal. */
void nxusServerInit(void);
/* Terminal shutdown of everything this file owns.  Cancels and JOINS the
   pointer-scan worker (it used to outlive every exit path), cancels a running scan
   and then releases the session through nxusSessionExit().  Idempotent: a second
   call returns without touching the already closed worker Thread.

   It also raises the terminal gate: from here on nxusServerHandle() refuses every
   command except Nop with NXUS_ERR_BAD_STATE + NXUS_REASON_BUSY_STATE and
   nxusServerTick() does nothing, so the connection thread (which keeps running until
   nxusNetExit(), see __appExit in main.c) cannot reach the state this function
   releases.  Only nxusServerInit() clears the gate again.

   Call it from the exit path BEFORE nxusDebugExit() and nxusNetExit() - the worker
   and the connection-thread handlers read target memory through the debug handle
   and through the session, so both have to be stopped first (see __appExit in
   main.c for the full order).

   Returns true only when the pointer-scan worker and every in-flight handler were
   drained, i.e. the session/views were really released and no reader of the debug
   handle or dmnt is left: the caller may then tear those down.  Returns false when
   either drain timed out and this function deliberately leaked the session (the
   "leak, never UAF" path).  In that case the caller MUST NOT call nxusDebugExit(),
   nxusNetExit() or nxusDmntExit(): the stuck worker/handler still reads through
   them.  Once the first call has completed, a later call returns its outcome; a call
   that races the first one while it is still draining conservatively returns false
   (not quiesced yet). */
bool nxusServerExit(void);
/* One packet, handled on the connection thread.

   The terminal gate is the first statement: once nxusServerExit() has run, every
   command except Nop is answered with NXUS_ERR_BAD_STATE + NXUS_REASON_BUSY_STATE
   without running a handler (the socket outlives the server teardown).  Nop stays
   served: it is the protocol's liveness probe, has no payload and touches no state.
   The header/seq are echoed back in the reply, as for every other command. */
void nxusServerHandle(int fd, const NxusPacketHeader *header, const u8 *payload, u32 length, void *user);
/* Called periodically from the main loop: watchdog + deferred work.  A no-op after
   nxusServerExit() (everything it would maintain has been released). */
void nxusServerTick(void);

/* ---- which commands may run concurrently --------------------------------
 *
 * The TCP transport serves up to NXUS_NET_MAX_CLIENTS connections at once, one
 * thread per connection (shared/nxus_net.h).  Every command is therefore either
 * READ-ONLY - several connections may run it at the same time - or MUTATING, in
 * which case nxus_server.c runs it under one global command mutex, so the session
 * state (scan/hit list, snapshots, freeze table, debug handle, cheat engine,
 * config) is still only ever changed by one command at a time.  That is the
 * invariant the old single-connection server got for free, and it is why the
 * read-only set is a whitelist: anything not listed here is treated as mutating.
 *
 * The split follows what the command does, not which subsystem it belongs to:
 *
 *   read-only : observe state - status/metadata, mapping/module/process views,
 *               memory reads/queries, scan status/hits, frozen/cheat/debug LIST
 *               and status reads, the log.
 *   mutating  : change state - start/refine/cancel/reset a scan, capture or
 *               release snapshots, pointer-scan begin/get and cheat export (they
 *               read the shared chain list a walk replaces), write memory, enable
 *               or disable a freeze/cheat, attach/detach/continue/step the
 *               debugger, set registers/breakpoints/hits, config, pause, resume.
 *
 * Deliberate exceptions, all for liveness:
 *   - Nop is read-only: the protocol's "are you still there?" probe touches no
 *     state.
 *   - Heartbeat is read-only: it only refreshes the session's idle clock, and it
 *     must keep flowing while another client is inside a long mutating command -
 *     otherwise the pause watchdog would resume the target mid-operation.
 *   - GetMetadata/GetStatus publish the identity cache they read; they are reads
 *     for every other purpose and must not wait behind a 90 s scan.
 *
 * Snapshot commands and the pointer-scan commands are NOT part of the scan family
 * below even though they are also scans in the user's sense: they own their own
 * slots/worker and already refuse each other (and a running search) through the
 * existing BUSY gates, while the "scan session" this header talks about is the hit
 * list plus the scan worker.
 */
static inline bool nxusServerCommandIsReadOnly(u16 cmd) {
    switch (cmd) {
        /* liveness only */
        case NxusCmd_Nop:
        case NxusCmd_Heartbeat:
        /* status / identity */
        case NxusCmd_GetStatus:
        case NxusCmd_GetMetadata:
        /* address-space views and memory reads */
        case NxusCmd_GetModules:
        case NxusCmd_GetProcesses:
        case NxusCmd_GetMappingCount:
        case NxusCmd_GetMappings:
        case NxusCmd_Query:
        case NxusCmd_Read:
        /* scan results (the scan mutations are listed below) */
        case NxusCmd_ScanStatus:
        case NxusCmd_ScanGetHits:
        /* freeze / cheat list reads */
        case NxusCmd_FrozenList:
        case NxusCmd_CheatList:
        case NxusCmd_CheatStatus:
        /* debugger reads */
        case NxusCmd_DebugStatus:
        case NxusCmd_BreakList:
        case NxusCmd_ThreadList:
        case NxusCmd_RegsGet:
        case NxusCmd_HitGet:
        /* log */
        case NxusCmd_LogGet:
        /* Defined in the protocol but not implemented by this build: classify by
           intent so a future handler lands on the right side. */
        case NxusCmd_ProbeGet:
            return true;

        /* Everything else - including Pause/Resume, ForceOpen/Close, Write, the
           scan mutations, both snapshot sides, PtrScanBegin/PtrScanGet,
           CheatExport, FrozenEnable/Disable, CheatToggle, the debug attach/detach/
           continue/step and register/breakpoint/hit mutations, Config, ProbeRun
           and the cheat upload/run commands - changes state or reads state a
           mutating command replaces, and is serialised.  The default is "mutating"
           so an unknown/future command id can never run concurrently with a
           command that does something. */
        default:
            return false;
    }
}

/* Commands that read or drive the shared search session (the hit list and the
 * scan worker).  The connection that successfully starts or refines a scan owns
 * that session until it disconnects: another client asking for the status or the
 * hits, or trying to start/refine/cancel one, is answered with
 * NXUS_REASON_BUSY_STATE instead of being shown - or allowed to disturb - the
 * owner's results.  Keep this a subset of the commands dispatchCommand() handles:
 * the host test walks every NxusCmd value and pins both classifications. */
static inline bool nxusServerCommandIsScanFamily(u16 cmd) {
    switch (cmd) {
        case NxusCmd_ScanBegin:
        case NxusCmd_ScanNext:
        case NxusCmd_ScanStatus:
        case NxusCmd_ScanCancel:
        case NxusCmd_ScanGetHits:
        case NxusCmd_ScanReset:
        case NxusCmd_ScanUndo:
            return true;
        default:
            return false;
    }
}

/* True from the moment nxusServerExit() raised the terminal gate (until the next
   nxusServerInit()).  Exposed for the workers this file does not own: a thread that
   outlives the dispatcher (the cheat VM worker in nxus_cheat_srv.c) polls it so it
   can never start another tick against the session/dmnt the exit path is releasing.
   Not a substitute for joining such a worker - main.c still stops it BEFORE
   nxusServerExit() - it is the belt to that brace. */
bool nxusServerHasExited(void);
