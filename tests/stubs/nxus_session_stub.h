/*
 * Test double for the part of the Nxus scan session that the snapshot service
 * touches.
 *
 * switch/source/nxus_snapshot_srv.c is a Switch unit: it asks the session for
 * the target identity, pins the published region list and reads target memory
 * through it.  On the host none of that exists (no dmnt:cht, no libnx, no scan
 * worker), so this stub supplies exactly those entry points and lets the test
 * decide what the "target" is:
 *
 *   - pid / program id / session id are settable, which is the identity the
 *     service stamps a capture with,
 *   - the one region is a plain 256 KB buffer the test can fill or mutate,
 *   - the reader can be made to refuse every read (a capture that hashes zero
 *     blocks - the failure path a take must leave no stamp on),
 *   - view pinning can be refused (the "no view pin available" failure path),
 *   - region preparation can return a failure (the path before any pin is taken).
 *
 * tests/stubs/switch.h provides the libnx surface (Result/u8/u64/MAKERESULT),
 * so nothing here is libnx-specific.  Only tests/test_snapshot_owner.c links this
 * file; the SHIPPED nxus_snapshot_srv.c is what runs against it.
 */
#pragma once

#include <switch.h>

/* The fake target used by the owner tests. */
#define NXUS_TEST_PID_A 0x100ull
#define NXUS_TEST_PID_B 0x200ull
#define NXUS_TEST_TITLE_A 0x0100000000001000ull
#define NXUS_TEST_TITLE_B 0x0100000000002000ull

#define NXUS_TEST_REGION_BASE 0x36000000ull
#define NXUS_TEST_REGION_SIZE (256u * 1024u)

/* Default state: pid A / title A / session 1, readable, pin available, empty
   target memory, cleared counters and log. */
void nxusTestSessionReset(void);

/* Simulate the session moving to another target between calls. */
void nxusTestSessionSetIdentity(u64 pid, u64 program_id, u32 session_id);

/* false: nxusSessionReadCallback() refuses every read. */
void nxusTestSessionSetReadable(bool readable);

/* false: nxusSessionViewPinCurrent() fails, like a full pin table or a dead
   session. */
void nxusTestSessionSetPinAvailable(bool available);

/* Result nxusSessionPrepareRegions() returns (0 = succeed). */
void nxusTestSessionSetPrepareResult(Result rc);

/* Observability of what the service under test did. */
u32 nxusTestSessionPrepareCalls(void);
u32 nxusTestSessionReads(void);
u32 nxusTestSessionOutstandingPins(void);

/* The one fake region and its backing bytes. */
u8        *nxusTestSessionMemory(void);
u64        nxusTestSessionRegionBase(void);
u32        nxusTestSessionRegionSize(void);

/* Newest nxusLogWrite()/nxusLogWriteError() line: the service's diagnostics are
   part of the contract (the refusal must name both captures), so tests assert on
   the text it produced. */
const char *nxusTestLastLog(void);
void        nxusTestLogClear(void);
