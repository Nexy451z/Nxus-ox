/*
 * Test double for the console surface that switch/source/nxus_cheat_srv.c uses.
 *
 * The cheat service is a Switch unit: it reads the target through the session /
 * dmnt wrapper, samples the HID mask, honours the server's terminal gate and
 * reports faults with an asynchronous event.  On the host none of that exists, so
 * this stub supplies exactly those entry points and lets the test decide what the
 * "target" is:
 *
 *   - pid / program id / dmnt incarnation are settable, which is the identity the
 *     service stamps an upload with and compares against on every tick,
 *   - the target memory is a plain 1 MiB buffer the test can seed and inspect,
 *   - writes can be made to fail (target gone / read-only page), reads too,
 *   - the range policy can be refused, and the stub records WHICH of the two
 *     policies was asked (readable+writable vs readable+(writable|executable)),
 *   - the held-button mask is settable and its reads are counted (the service has
 *     to sample it on every tick, not once at upload),
 *   - NXUS_EVENT_* sends are recorded (type + payload) so the CheatFault contract
 *     can be asserted,
 *   - log lines are captured, because the service's diagnostics are part of the
 *     contract (a fault must name the target it was uploaded for).
 *
 * tests/stubs/switch.h provides the libnx surface (Result/u8/u64/Mutex/Thread/
 * MAKERESULT/svcSleepThread).  Its threadCreate() reports failure on purpose, so no
 * real worker exists: the test drives the shipped cheatSrvWorkerStep() directly
 * (the shipped .c is INCLUDED, like test_snapshot_owner.c does, which is what makes
 * that static step reachable).
 */
#pragma once

#include <switch.h>

#include "nxus_protocol.h"

/* The fake target used by the cheat-service tests. */
#define CHEAT_TEST_PID_A   0x111ull
#define CHEAT_TEST_PID_B   0x222ull
#define CHEAT_TEST_TITLE_A 0x0100000000001000ull
#define CHEAT_TEST_TITLE_B 0x0100000000002000ull

#define CHEAT_TEST_BASE 0x10000000ull
#define CHEAT_TEST_SIZE (1024u * 1024u)

/* Back to target A / incarnation 1 / writable / readable / range allowed / empty
 * memory / no events / cleared counters and log. */
void cheatTestReset(void);

void cheatTestSetIdentity(u64 pid, u64 program_id);
void cheatTestSetIncarnation(u32 incarnation);
/* true: nxusSessionTargetIdentity() reports "the writer won the race". */
void cheatTestSetIdentityBroken(bool broken);
void cheatTestSetReadable(bool readable);
void cheatTestSetWritable(bool writable);
void cheatTestSetRangeAllowed(bool allowed);
void cheatTestSetDebugAttached(bool attached);
void cheatTestSetServerExited(bool exited);
void cheatTestSetHeldMask(u64 mask);

/* Target memory, seeded directly (not counted as a writer call). */
u8  *cheatTestMemory(void);
void cheatTestPoke(u64 address, const void *data, u32 size);
u32  cheatTestPeekU32(u64 address);

/* Observability of what the service under test did. */
u32 cheatTestWrites(void);          /* every nxusDmntWrite the service issued */
u32 cheatTestWritesOk(void);        /* the ones that were accepted */
u32 cheatTestPlainRangeChecks(void);/* nxusSessionCheckRange(..., true) calls */
u32 cheatTestPatchRangeChecks(void);/* nxusSessionCheckCodePatchRange() calls */
u32 cheatTestHeldMaskReads(void);
u32 cheatTestReads(void);

u32 cheatTestEventCount(void);
u16 cheatTestLastEventType(void);
u32 cheatTestLastEventLength(void);
const NxusCheatFault *cheatTestLastFault(void);
void cheatTestClearEvents(void);

const char *cheatTestLastLog(void);
void        cheatTestLogClear(void);
