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
void nxusServerHandle(int fd, const NxusPacketHeader *header, const u8 *payload, u32 length, void *user);
/* Called periodically from the main loop: watchdog + deferred work. */
void nxusServerTick(void);
