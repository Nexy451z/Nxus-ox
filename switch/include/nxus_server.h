/* Nxus command dispatcher. */
#pragma once

#include <switch.h>

#include "nxus_protocol.h"

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

void nxusServerInit(void);
/* Terminal shutdown of everything this file owns.  Cancels and JOINS the
   pointer-scan worker (it used to outlive every exit path), cancels a running scan
   and then releases the session through nxusSessionExit().  Idempotent: a second
   call returns without touching the already closed worker Thread.

   Call it from the exit path BEFORE nxusDebugExit() and nxusNetExit() - the worker
   and the connection-thread handlers read target memory through the debug handle
   and through the session, so both have to be stopped first (see __appExit in
   main.c for the full order). */
void nxusServerExit(void);
void nxusServerHandle(int fd, const NxusPacketHeader *header, const u8 *payload, u32 length, void *user);
/* Called periodically from the main loop: watchdog + deferred work. */
void nxusServerTick(void);
