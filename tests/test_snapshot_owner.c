/*
 * Host tests for the target-owner logic of the snapshot service
 * (switch/source/nxus_snapshot_srv.c).
 *
 * A snapshot is only a table of per-block hashes of ONE process's memory, so an
 * A/B diff is meaningful only while both slots still describe the same target
 * the session is on.  The service now stamps every successful capture with
 * {pid, program_id, session_id} and refuses a diff otherwise; until this test
 * existed only core/nxus_snapshot.c was compiled on the host, so that logic was
 * never exercised outside the console.
 *
 * Like test_session_view.c, this test includes the SHIPPED service source rather
 * than a copy of it (run_tests.sh supplies tests/stubs/switch.h and
 * tests/stubs/nxus_session_stub.c for the libnx/dmnt surface).  Including it is
 * deliberate: the per-slot and cached-diff owner stamps are static state, and
 * "a release / a failed take leaves no stamp behind" cannot be observed through
 * the public API, because an invalidated slot is refused for having no capture
 * before the stamp is ever consulted.
 *
 * Covered contract:
 *   - same identity on A and B -> diff succeeds and pages its rows,
 *   - different title or different pid between A and B -> BAD_STATE + the log
 *     line naming both captures (also in reversed argument order),
 *   - captures that no longer match the session's CURRENT target -> BAD_STATE
 *     (and the cached rows stop being pageable before the refusal is re-run),
 *   - same pid with a new session generation (scan/Reset) or an unknown program
 *     id (DebugAttach) still diffs - the owner rule must not over-refuse,
 *   - a failed capture (zero blocks, no view pin, region prepare error) leaves
 *     the slot uncaptured and unstamped, and clears any previous stamp of it,
 *   - nxusSnapshotReleaseAll() frees the slots AND drops both stamps and the
 *     cached diff, so a later capture cannot be compared against a released one,
 *   - nxusSnapshotDiffMatchesCurrent() tracks exactly the cached changed list.
 */
#include <stdio.h>
#include <string.h>

#include "nxus_snapshot_srv.h"
#include "nxus_session_stub.h"

#include "../switch/source/nxus_snapshot_srv.c"

static int g_checks = 0;
static int g_failures = 0;

#define CHECK(cond, ...) do {                                        \
        g_checks++;                                                  \
        if (!(cond)) {                                               \
            g_failures++;                                            \
            printf("  FAIL %s:%d: ", __FILE__, __LINE__);            \
            printf(__VA_ARGS__);                                     \
            printf("\n");                                            \
        }                                                            \
    } while (0)

#define BAD_STATE ((Result)NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE))

#define REGION_SIZE   NXUS_TEST_REGION_SIZE
#define BLOCK_SIZE    4096u
#define REGION_BLOCKS (REGION_SIZE / BLOCK_SIZE)          /* 64 blocks */
#define SLOT_BYTES    (2ull * (u64)NXUS_SNAPSHOT_MAX_BLOCKS * (u64)sizeof(u64))

/* ---- helpers ------------------------------------------------------------ */

/* Start every section from the state the console has at boot: no captures, no
   cached diff, no allocated slot storage, and a fresh fake target A. */
static void fresh(void) {
    nxusSnapshotReleaseAll();
    nxusTestSessionReset();
}

static u8 *memory(void) { return nxusTestSessionMemory(); }

static Result takeSlotSummary(u32 slot, NxusSnapshotSummary *out) {
    memset(out, 0, sizeof(*out));
    return nxusSnapshotTake(slot, NxusScope_All, 0, 0, BLOCK_SIZE, out);
}

static Result takeSlot(u32 slot) {
    NxusSnapshotSummary scratch;
    return takeSlotSummary(slot, &scratch);
}

static Result compareSlots(u32 from, u32 to, NxusSnapshotSummary *out) {
    memset(out, 0, sizeof(*out));
    return nxusSnapshotCompare(from, to, out);
}

/* Page the whole cached changed list the way the server does. */
static u32 pageAll(void) {
    NxusChangedBlockWire rows[64];
    u32 total = 0;
    while (total < 100000u) {
        u32 n = nxusSnapshotGetChanged(rows, 64, total);
        if (n == 0) break;
        total += n;
    }
    return total;
}

static int stampEquals(u32 slot, u64 pid, u64 program_id, u32 session_id) {
    const NxusSnapshotOwner *o = &g_SlotOwner[slot];
    return o->valid && o->pid == pid && o->program_id == program_id &&
           o->session_id == session_id;
}

static int diffStampEquals(u64 pid, u64 program_id, u32 session_id) {
    const NxusSnapshotOwner *o = &g_DiffOwner;
    return o->valid && o->pid == pid && o->program_id == program_id &&
           o->session_id == session_id;
}

static void expectLog(const char *expected) {
    const char *actual = nxusTestLastLog();
    CHECK(strcmp(actual, expected) == 0,
          "log line differs\n    expected: \"%s\"\n    actual:   \"%s\"",
          expected, actual);
}

/* The refusal for two captures of different targets names slot A and slot B
   (never the argument order), with pid in decimal and the title as 16 hex
   digits. */
static void expectDiffTargetsLog(u64 pid_a, u64 title_a, u64 pid_b, u64 title_b) {
    char expected[256];
    snprintf(expected, sizeof(expected),
             "snapshot: slots were captured for different targets "
             "(A pid=%llu title=%016llX, B pid=%llu title=%016llX) - capture both again",
             (unsigned long long)pid_a, (unsigned long long)title_a,
             (unsigned long long)pid_b, (unsigned long long)title_b);
    expectLog(expected);
}

/* The pair is fine but the session has moved away from what it describes. */
static void expectCurrentTargetLog(char from, char to, u64 pid_captured,
                                   u64 title_captured, u64 pid_now, u64 title_now) {
    char expected[320];
    snprintf(expected, sizeof(expected),
             "snapshot diff %c->%c: captures were taken on pid=%llu title=%016llX "
             "but the current target is pid=%llu title=%016llX - capture both again",
             from, to,
             (unsigned long long)pid_captured, (unsigned long long)title_captured,
             (unsigned long long)pid_now, (unsigned long long)title_now);
    expectLog(expected);
}

/* ---- same target -------------------------------------------------------- */

static void testSameTargetDiffSucceeds(void) {
    printf("[test] same target: A/B diff succeeds and pages its rows\n");
    fresh();
    nxusTestSessionSetIdentity(NXUS_TEST_PID_A, NXUS_TEST_TITLE_A, 1);
    memset(memory(), 0x11, REGION_SIZE);

    NxusSnapshotSummary a, b, d;
    Result rc = takeSlotSummary(0, &a);
    CHECK(R_SUCCEEDED(rc), "capture A rc=0x%08X", (unsigned)rc);
    CHECK(a.block_count == REGION_BLOCKS, "A counted %u blocks (expected %u)",
          (unsigned)a.block_count, (unsigned)REGION_BLOCKS);
    CHECK(a.block_size == BLOCK_SIZE, "A block size %u", (unsigned)a.block_size);
    CHECK(a.changed_count == 0 && a.truncated == 0,
          "a capture summary carries no previous diff (changed=%u truncated=%u)",
          (unsigned)a.changed_count, (unsigned)a.truncated);

    rc = takeSlotSummary(1, &b);
    CHECK(R_SUCCEEDED(rc), "capture B rc=0x%08X", (unsigned)rc);
    CHECK(b.block_count == REGION_BLOCKS, "B counted %u blocks", (unsigned)b.block_count);

    CHECK(stampEquals(0, NXUS_TEST_PID_A, NXUS_TEST_TITLE_A, 1),
          "slot A is stamped with the capture's target");
    CHECK(stampEquals(1, NXUS_TEST_PID_A, NXUS_TEST_TITLE_A, 1),
          "slot B is stamped with the capture's target");
    CHECK(!g_DiffOwner.valid, "no diff owner before the first compare");
    CHECK(nxusSnapshotDiffMatchesCurrent(), "no cached diff -> servable");

    rc = compareSlots(0, 1, &d);
    CHECK(R_SUCCEEDED(rc), "same-target diff rc=0x%08X", (unsigned)rc);
    CHECK(d.changed_count == 0, "same target, no writes -> %u changed", (unsigned)d.changed_count);
    CHECK(d.truncated == 0, "clean diff must not be truncated (%u)", (unsigned)d.truncated);
    CHECK(d.block_count == REGION_BLOCKS, "diff summary describes B (%u blocks)",
          (unsigned)d.block_count);
    CHECK(diffStampEquals(NXUS_TEST_PID_A, NXUS_TEST_TITLE_A, 1),
          "the diff is stamped with the FROM slot's identity");
    CHECK(nxusSnapshotDiffMatchesCurrent(), "same-target diff is servable");
    CHECK(pageAll() == 0, "no rows to page");

    /* One changed block, still the same target. */
    memory()[0x8000] ^= 0xFF;
    rc = takeSlotSummary(1, &b);
    CHECK(R_SUCCEEDED(rc), "recapture B rc=0x%08X", (unsigned)rc);
    CHECK(b.changed_count == 0, "a new capture ends the previous diff (%u)",
          (unsigned)b.changed_count);
    CHECK(!g_DiffOwner.valid, "a new capture drops the diff owner");

    rc = compareSlots(0, 1, &d);
    CHECK(R_SUCCEEDED(rc), "diff after one write rc=0x%08X", (unsigned)rc);
    CHECK(d.changed_count == 1, "expected 1 changed block, got %u", (unsigned)d.changed_count);
    CHECK(pageAll() == 1, "paging returns the one changed row");

    NxusChangedBlockWire row;
    memset(&row, 0, sizeof(row));
    CHECK(nxusSnapshotGetChanged(&row, 1, 0) == 1, "one row at offset 0");
    CHECK(row.address == NXUS_TEST_REGION_BASE + 0x8000, "row address %llx",
          (unsigned long long)row.address);
    CHECK(row.size == BLOCK_SIZE, "row size %u", (unsigned)row.size);
    CHECK(row.flags == NXUS_CHANGE_CHANGED, "row flags %u", (unsigned)row.flags);
    CHECK(nxusSnapshotGetChanged(&row, 1, 1) == 0, "offset past the list pages nothing");
}

/* ---- title / pid mismatches between the two captures -------------------- */

static void testTitleSwitchRefused(void) {
    printf("[test] title switch between A and B -> BAD_STATE + named log\n");
    fresh();
    nxusTestSessionSetIdentity(NXUS_TEST_PID_A, NXUS_TEST_TITLE_A, 1);
    memset(memory(), 0x33, REGION_SIZE);
    CHECK(R_SUCCEEDED(takeSlot(0)), "capture A on title A");

    nxusTestSessionSetIdentity(NXUS_TEST_PID_B, NXUS_TEST_TITLE_B, 2);
    memset(memory(), 0x44, REGION_SIZE);
    CHECK(R_SUCCEEDED(takeSlot(1)), "capture B on title B");
    CHECK(stampEquals(0, NXUS_TEST_PID_A, NXUS_TEST_TITLE_A, 1), "A keeps its stamp");
    CHECK(stampEquals(1, NXUS_TEST_PID_B, NXUS_TEST_TITLE_B, 2), "B keeps its stamp");

    NxusSnapshotSummary d;
    Result rc = compareSlots(0, 1, &d);
    CHECK(rc == BAD_STATE, "title-crossing diff rc=0x%08X", (unsigned)rc);
    expectDiffTargetsLog(NXUS_TEST_PID_A, NXUS_TEST_TITLE_A,
                         NXUS_TEST_PID_B, NXUS_TEST_TITLE_B);
    CHECK(d.changed_count == 0, "refused diff reports no changed rows (%u)",
          (unsigned)d.changed_count);
    CHECK(!g_DiffOwner.valid, "refused diff publishes no diff owner");
    CHECK(pageAll() == 0, "nothing is pageable after a refused diff");
    CHECK(nxusSnapshotDiffMatchesCurrent(), "a refused diff leaves nothing stale");

    /* The log labels the SLOTS in A/B order whatever order the client passed. */
    rc = compareSlots(1, 0, &d);
    CHECK(rc == BAD_STATE, "reversed title-crossing diff rc=0x%08X", (unsigned)rc);
    expectDiffTargetsLog(NXUS_TEST_PID_A, NXUS_TEST_TITLE_A,
                         NXUS_TEST_PID_B, NXUS_TEST_TITLE_B);

    /* Same pid, different title: the title changed between the two captures. */
    fresh();
    nxusTestSessionSetIdentity(NXUS_TEST_PID_A, NXUS_TEST_TITLE_A, 1);
    CHECK(R_SUCCEEDED(takeSlot(0)), "capture A on title A");
    nxusTestSessionSetIdentity(NXUS_TEST_PID_A, NXUS_TEST_TITLE_B, 1);
    CHECK(R_SUCCEEDED(takeSlot(1)), "capture B of title B under the same pid");
    rc = compareSlots(0, 1, &d);
    CHECK(rc == BAD_STATE, "same-pid title switch must be refused (rc=0x%08X)", (unsigned)rc);
    expectDiffTargetsLog(NXUS_TEST_PID_A, NXUS_TEST_TITLE_A,
                         NXUS_TEST_PID_A, NXUS_TEST_TITLE_B);
}

static void testRelaunchAndCurrentTargetMoves(void) {
    printf("[test] relaunch / moved target -> BAD_STATE\n");
    fresh();

    /* Relaunch between the two captures: same title, new pid. */
    nxusTestSessionSetIdentity(NXUS_TEST_PID_A, NXUS_TEST_TITLE_A, 1);
    memset(memory(), 0x55, REGION_SIZE);
    CHECK(R_SUCCEEDED(takeSlot(0)), "capture A");
    nxusTestSessionSetIdentity(NXUS_TEST_PID_B, NXUS_TEST_TITLE_A, 2);
    memset(memory(), 0x66, REGION_SIZE);
    CHECK(R_SUCCEEDED(takeSlot(1)), "capture B after the relaunch");
    CHECK(stampEquals(0, NXUS_TEST_PID_A, NXUS_TEST_TITLE_A, 1), "A stamped with the old pid");
    CHECK(stampEquals(1, NXUS_TEST_PID_B, NXUS_TEST_TITLE_A, 2), "B stamped with the new pid");

    NxusSnapshotSummary d;
    Result rc = compareSlots(0, 1, &d);
    CHECK(rc == BAD_STATE, "relaunch diff rc=0x%08X", (unsigned)rc);
    expectDiffTargetsLog(NXUS_TEST_PID_A, NXUS_TEST_TITLE_A,
                         NXUS_TEST_PID_B, NXUS_TEST_TITLE_A);
    CHECK(d.changed_count == 0, "relaunch refusal reports no rows (%u)",
          (unsigned)d.changed_count);
    CHECK(pageAll() == 0, "relaunch refusal pages nothing");

    /* The pair agrees, but the session has moved to another pid afterwards. */
    fresh();
    nxusTestSessionSetIdentity(NXUS_TEST_PID_A, NXUS_TEST_TITLE_A, 1);
    memset(memory(), 0x55, REGION_SIZE);
    CHECK(R_SUCCEEDED(takeSlot(0)), "capture A");
    memset(memory(), 0x66, REGION_SIZE);
    CHECK(R_SUCCEEDED(takeSlot(1)), "capture B");
    rc = compareSlots(0, 1, &d);
    CHECK(R_SUCCEEDED(rc), "diff on the pair rc=0x%08X", (unsigned)rc);
    CHECK(d.changed_count == REGION_BLOCKS, "all %u blocks differ (%u)",
          (unsigned)REGION_BLOCKS, (unsigned)d.changed_count);
    CHECK(nxusSnapshotDiffMatchesCurrent(), "diff servable on its target");
    CHECK(pageAll() == REGION_BLOCKS, "all changed rows page on the target");

    nxusTestSessionSetIdentity(NXUS_TEST_PID_B, NXUS_TEST_TITLE_A, 2);
    CHECK(!nxusSnapshotDiffMatchesCurrent(), "rows of the old pid are not servable");
    CHECK(pageAll() == 0, "no stale row is served after the relaunch");
    rc = compareSlots(0, 1, &d);
    CHECK(rc == BAD_STATE, "diff after the relaunch rc=0x%08X", (unsigned)rc);
    expectCurrentTargetLog('A', 'B', NXUS_TEST_PID_A, NXUS_TEST_TITLE_A,
                           NXUS_TEST_PID_B, NXUS_TEST_TITLE_A);
    CHECK(d.changed_count == 0, "the refused diff cleared the rows (%u)",
          (unsigned)d.changed_count);
    CHECK(!g_DiffOwner.valid, "the refused diff dropped the cached owner");

    /* Back on the captures' target: the pair is still valid, no recapture. */
    nxusTestSessionSetIdentity(NXUS_TEST_PID_A, NXUS_TEST_TITLE_A, 1);
    rc = compareSlots(0, 1, &d);
    CHECK(R_SUCCEEDED(rc), "diff after returning to the target rc=0x%08X", (unsigned)rc);
    CHECK(d.changed_count == REGION_BLOCKS, "%u changed blocks again", (unsigned)d.changed_count);
    CHECK(nxusSnapshotDiffMatchesCurrent(), "the re-run diff is servable");
    CHECK(pageAll() == REGION_BLOCKS, "the re-run diff pages");

    /* Another title (pid and title both move). */
    nxusTestSessionSetIdentity(NXUS_TEST_PID_B, NXUS_TEST_TITLE_B, 3);
    rc = compareSlots(0, 1, &d);
    CHECK(rc == BAD_STATE, "diff after a title switch rc=0x%08X", (unsigned)rc);
    expectCurrentTargetLog('A', 'B', NXUS_TEST_PID_A, NXUS_TEST_TITLE_A,
                           NXUS_TEST_PID_B, NXUS_TEST_TITLE_B);
}

/* ---- identity rules that must NOT refuse -------------------------------- */

static void testSamePidRules(void) {
    printf("[test] same pid + generation/unknown-title changes still diff\n");

    /* A scan or Reset bumps the session generation on the same target. */
    fresh();
    nxusTestSessionSetIdentity(NXUS_TEST_PID_A, NXUS_TEST_TITLE_A, 1);
    memset(memory(), 0x10, REGION_SIZE);
    CHECK(R_SUCCEEDED(takeSlot(0)), "capture A (session 1)");
    nxusTestSessionSetIdentity(NXUS_TEST_PID_A, NXUS_TEST_TITLE_A, 9);
    CHECK(R_SUCCEEDED(takeSlot(1)), "capture B (session 9)");
    CHECK(stampEquals(0, NXUS_TEST_PID_A, NXUS_TEST_TITLE_A, 1), "A keeps session 1");
    CHECK(stampEquals(1, NXUS_TEST_PID_A, NXUS_TEST_TITLE_A, 9), "B carries session 9");

    NxusSnapshotSummary d;
    Result rc = compareSlots(0, 1, &d);
    CHECK(R_SUCCEEDED(rc), "same pid/title, new generation diff rc=0x%08X", (unsigned)rc);
    CHECK(d.changed_count == 0, "generation bump is not a change (%u)", (unsigned)d.changed_count);
    CHECK(diffStampEquals(NXUS_TEST_PID_A, NXUS_TEST_TITLE_A, 1),
          "the diff keeps the FROM slot's stamp");
    CHECK(nxusSnapshotDiffMatchesCurrent(), "the diff matches the current target");

    /* DebugAttach: dmnt metadata unknown (program id 0) on both sides. */
    fresh();
    nxusTestSessionSetIdentity(NXUS_TEST_PID_A, 0, 1);
    memset(memory(), 0x20, REGION_SIZE);
    CHECK(R_SUCCEEDED(takeSlot(0)), "capture A (title unknown)");
    nxusTestSessionSetIdentity(NXUS_TEST_PID_A, 0, 2);
    CHECK(R_SUCCEEDED(takeSlot(1)), "capture B (title unknown)");
    rc = compareSlots(0, 1, &d);
    CHECK(R_SUCCEEDED(rc), "unknown title, same pid diff rc=0x%08X", (unsigned)rc);
    CHECK(d.changed_count == 0, "changed=%u", (unsigned)d.changed_count);
    CHECK(nxusSnapshotDiffMatchesCurrent(), "servable while the title is unknown");

    /* Captures know the title, the current target's title became unknown. */
    fresh();
    nxusTestSessionSetIdentity(NXUS_TEST_PID_A, NXUS_TEST_TITLE_A, 1);
    memset(memory(), 0x30, REGION_SIZE);
    CHECK(R_SUCCEEDED(takeSlot(0)), "capture A");
    CHECK(R_SUCCEEDED(takeSlot(1)), "capture B");
    nxusTestSessionSetIdentity(NXUS_TEST_PID_A, 0, 1);
    rc = compareSlots(0, 1, &d);
    CHECK(R_SUCCEEDED(rc), "unknown CURRENT title must not refuse (rc=0x%08X)", (unsigned)rc);
    CHECK(d.changed_count == 0, "changed=%u", (unsigned)d.changed_count);

    /* Captures have no title, the current target does. */
    fresh();
    nxusTestSessionSetIdentity(NXUS_TEST_PID_A, 0, 1);
    memset(memory(), 0x40, REGION_SIZE);
    CHECK(R_SUCCEEDED(takeSlot(0)), "capture A (title unknown)");
    CHECK(R_SUCCEEDED(takeSlot(1)), "capture B (title unknown)");
    nxusTestSessionSetIdentity(NXUS_TEST_PID_A, NXUS_TEST_TITLE_A, 1);
    rc = compareSlots(0, 1, &d);
    CHECK(R_SUCCEEDED(rc), "known CURRENT title with unknown captures rc=0x%08X", (unsigned)rc);
    CHECK(d.changed_count == 0, "changed=%u", (unsigned)d.changed_count);
}

/* Without a pid (no target attached) the session generation is the only token,
   exactly like the hit-list owner check. */
static void testUnknownPidUsesGeneration(void) {
    printf("[test] unknown pid falls back to the session generation\n");
    fresh();
    nxusTestSessionSetIdentity(0, 0, 1);
    memset(memory(), 0x30, REGION_SIZE);
    CHECK(R_SUCCEEDED(takeSlot(0)), "capture A (no pid)");
    CHECK(R_SUCCEEDED(takeSlot(1)), "capture B (no pid)");
    CHECK(stampEquals(0, 0, 0, 1), "A stamp has pid 0, generation 1");
    CHECK(stampEquals(1, 0, 0, 1), "B stamp has pid 0, generation 1");

    NxusSnapshotSummary d;
    Result rc = compareSlots(0, 1, &d);
    CHECK(R_SUCCEEDED(rc), "same generation diff rc=0x%08X", (unsigned)rc);
    CHECK(d.changed_count == 0, "changed=%u", (unsigned)d.changed_count);

    nxusTestSessionSetIdentity(0, 0, 2);
    rc = compareSlots(0, 1, &d);
    CHECK(rc == BAD_STATE, "generation moved, diff rc=0x%08X", (unsigned)rc);
    expectCurrentTargetLog('A', 'B', 0, 0, 0, 0);
    CHECK(pageAll() == 0, "no rows after the generation moved");

    /* Two captures from different generations are different targets. */
    fresh();
    nxusTestSessionSetIdentity(0, 0, 1);
    CHECK(R_SUCCEEDED(takeSlot(0)), "capture A (generation 1)");
    nxusTestSessionSetIdentity(0, 0, 2);
    CHECK(R_SUCCEEDED(takeSlot(1)), "capture B (generation 2)");
    rc = compareSlots(0, 1, &d);
    CHECK(rc == BAD_STATE, "cross-generation diff rc=0x%08X", (unsigned)rc);
    expectDiffTargetsLog(0, 0, 0, 0);
}

/* ---- release ------------------------------------------------------------ */

static void testReleaseAllDropsStamps(void) {
    printf("[test] ReleaseAll frees the slots and drops every stamp\n");
    fresh();
    nxusTestSessionSetIdentity(NXUS_TEST_PID_A, NXUS_TEST_TITLE_A, 1);
    memset(memory(), 0x11, REGION_SIZE);
    CHECK(R_SUCCEEDED(takeSlot(0)), "capture A");
    memset(memory(), 0x22, REGION_SIZE);
    CHECK(R_SUCCEEDED(takeSlot(1)), "capture B");

    NxusSnapshotSummary d;
    Result rc = compareSlots(0, 1, &d);
    CHECK(R_SUCCEEDED(rc), "diff rc=0x%08X", (unsigned)rc);
    CHECK(d.changed_count == REGION_BLOCKS, "%u changed blocks", (unsigned)d.changed_count);
    CHECK(pageAll() == REGION_BLOCKS, "all changed rows page");
    CHECK(nxusSnapshotDiffMatchesCurrent(), "diff is servable before the release");
    CHECK(nxusSnapshotResidentSlots() == 3u, "both slots are resident (%u)",
          (unsigned)nxusSnapshotResidentSlots());
    CHECK(nxusSnapshotResidentBytes() == 2ull * SLOT_BYTES, "%llu resident bytes",
          (unsigned long long)nxusSnapshotResidentBytes());

    nxusSnapshotReleaseAll();
    {
        char expected[160];
        snprintf(expected, sizeof(expected),
                 "snapshot: both slots released (%llu B returned to the heap, "
                 "re-allocated by the next capture)",
                 (unsigned long long)(2ull * SLOT_BYTES));
        expectLog(expected);
    }

    CHECK(!g_SlotOwner[0].valid, "released slot A carries no stamp");
    CHECK(!g_SlotOwner[1].valid, "released slot B carries no stamp");
    CHECK(!g_DiffOwner.valid, "released diff carries no owner");
    CHECK(g_ChangedCount == 0, "released diff keeps no rows (%u)", (unsigned)g_ChangedCount);
    CHECK(g_Snapshots[0].count == 0 && g_Snapshots[0].block_size == 0,
          "released slot A has no grid (%u blocks, block size %u)",
          (unsigned)g_Snapshots[0].count, (unsigned)g_Snapshots[0].block_size);
    CHECK(g_Snapshots[1].count == 0 && g_Snapshots[1].block_size == 0,
          "released slot B has no grid (%u blocks, block size %u)",
          (unsigned)g_Snapshots[1].count, (unsigned)g_Snapshots[1].block_size);
    CHECK(g_Hashes[0] == NULL && g_Addresses[0] == NULL, "slot A storage was freed");
    CHECK(g_Hashes[1] == NULL && g_Addresses[1] == NULL, "slot B storage was freed");
    CHECK(nxusSnapshotResidentSlots() == 0u, "no slot is resident (%u)",
          (unsigned)nxusSnapshotResidentSlots());
    CHECK(nxusSnapshotResidentBytes() == 0u, "no resident bytes (%llu)",
          (unsigned long long)nxusSnapshotResidentBytes());
    CHECK(nxusSnapshotDiffMatchesCurrent(), "no cached diff after the release");
    CHECK(pageAll() == 0, "released rows are not pageable");

    NxusSnapshotSummary s;
    nxusSnapshotGetSummary(0, &s);
    CHECK(s.block_size == 0 && s.block_count == 0 && s.changed_count == 0,
          "released slot A summary is empty (grid %u, blocks %u, changed %u)",
          (unsigned)s.block_size, (unsigned)s.block_count, (unsigned)s.changed_count);
    nxusSnapshotGetSummary(1, &s);
    CHECK(s.block_size == 0 && s.block_count == 0,
          "released slot B summary is empty (grid %u, blocks %u)",
          (unsigned)s.block_size, (unsigned)s.block_count);

    /* A capture after the release cannot be compared against the freed slot. */
    nxusTestSessionSetIdentity(NXUS_TEST_PID_B, NXUS_TEST_TITLE_B, 2);
    CHECK(R_SUCCEEDED(takeSlot(1)), "capture B on the other title");
    CHECK(stampEquals(1, NXUS_TEST_PID_B, NXUS_TEST_TITLE_B, 2), "B is stamped");
    CHECK(!g_SlotOwner[0].valid, "the released slot did not regain a stamp");
    rc = compareSlots(0, 1, &d);
    CHECK(rc == BAD_STATE, "diff against a released slot rc=0x%08X", (unsigned)rc);
    expectLog("snapshot diff A->B: slot A holds no capture - refusing to compare");
    CHECK(d.changed_count == 0, "refusal reports no rows (%u)", (unsigned)d.changed_count);
    CHECK(pageAll() == 0, "refusal pages nothing");

    /* Re-capturing the released slot on the same target works from scratch. */
    CHECK(R_SUCCEEDED(takeSlot(0)), "re-capture A on title B");
    CHECK(stampEquals(0, NXUS_TEST_PID_B, NXUS_TEST_TITLE_B, 2), "A is stamped again");
    rc = compareSlots(0, 1, &d);
    CHECK(R_SUCCEEDED(rc), "diff of the re-captured pair rc=0x%08X", (unsigned)rc);
    CHECK(d.changed_count == 0, "identical captures -> %u changed", (unsigned)d.changed_count);
    CHECK(nxusSnapshotResidentSlots() == 3u, "both slots are resident again (%u)",
          (unsigned)nxusSnapshotResidentSlots());
    CHECK(nxusSnapshotResidentBytes() == 2ull * SLOT_BYTES, "%llu resident bytes",
          (unsigned long long)nxusSnapshotResidentBytes());
}

/* ---- failed captures ---------------------------------------------------- */

static void testFailedCaptureLeavesNoStamp(void) {
    printf("[test] a failed capture leaves the slot uncaptured and unstamped\n");
    fresh();
    nxusTestSessionSetIdentity(NXUS_TEST_PID_A, NXUS_TEST_TITLE_A, 1);
    memset(memory(), 0x55, REGION_SIZE);
    CHECK(R_SUCCEEDED(takeSlot(0)), "capture A");
    CHECK(R_SUCCEEDED(takeSlot(1)), "capture B");
    CHECK(stampEquals(1, NXUS_TEST_PID_A, NXUS_TEST_TITLE_A, 1), "B has a stamp to lose");

    /* Target memory disappears and the session moves: the take runs, hashes
       zero blocks, and must not publish either the new identity or the old
       stamp. */
    nxusTestSessionSetIdentity(NXUS_TEST_PID_B, NXUS_TEST_TITLE_B, 2);
    nxusTestSessionSetReadable(false);
    NxusSnapshotSummary d;
    Result rc = takeSlotSummary(1, &d);
    CHECK(rc == BAD_STATE, "zero-block capture rc=0x%08X", (unsigned)rc);
    expectLog("snapshot B: no block could be captured - slot B left uncaptured");
    CHECK(!g_SlotOwner[1].valid, "failed take left no stamp (not even the old one)");
    CHECK(g_Snapshots[1].count == 0 && g_Snapshots[1].block_size == 0,
          "failed take left no grid (%u blocks, block size %u)",
          (unsigned)g_Snapshots[1].count, (unsigned)g_Snapshots[1].block_size);
    CHECK(g_Hashes[1] != NULL, "the slot storage itself stays allocated");
    nxusSnapshotGetSummary(1, &d);
    CHECK(d.block_count == 0 && d.block_size == 0 && d.changed_count == 0,
          "failed take summary is empty (%u blocks, grid %u, changed %u)",
          (unsigned)d.block_count, (unsigned)d.block_size, (unsigned)d.changed_count);
    CHECK(!g_DiffOwner.valid && g_ChangedCount == 0, "failed take leaves no cached diff");
    CHECK(nxusSnapshotDiffMatchesCurrent(), "failed take leaves nothing stale");
    CHECK(nxusTestSessionOutstandingPins() == 0, "the failed take dropped its pin (%u)",
          (unsigned)nxusTestSessionOutstandingPins());

    rc = compareSlots(0, 1, &d);
    CHECK(rc == BAD_STATE, "diff against the failed slot rc=0x%08X", (unsigned)rc);
    expectLog("snapshot diff A->B: slot B holds no capture - refusing to compare");
    CHECK(stampEquals(0, NXUS_TEST_PID_A, NXUS_TEST_TITLE_A, 1),
          "the other slot keeps its own stamp");
    CHECK(d.changed_count == 0, "the refusal reports no rows (%u)", (unsigned)d.changed_count);

    /* Restoring memory and re-capturing B on the new target stamps it again;
       the diff now fails because A is on the old target, not because B is empty. */
    nxusTestSessionSetReadable(true);
    CHECK(R_SUCCEEDED(takeSlot(1)), "capture B after recovery");
    CHECK(stampEquals(1, NXUS_TEST_PID_B, NXUS_TEST_TITLE_B, 2), "B carries the new stamp");
    CHECK(stampEquals(0, NXUS_TEST_PID_A, NXUS_TEST_TITLE_A, 1), "A still carries its stamp");
    rc = compareSlots(0, 1, &d);
    CHECK(rc == BAD_STATE, "recovered B against old A rc=0x%08X", (unsigned)rc);
    expectDiffTargetsLog(NXUS_TEST_PID_A, NXUS_TEST_TITLE_A,
                         NXUS_TEST_PID_B, NXUS_TEST_TITLE_B);

    /* Failure before the capture: no view pin available. */
    fresh();
    nxusTestSessionSetIdentity(NXUS_TEST_PID_A, NXUS_TEST_TITLE_A, 1);
    nxusTestSessionSetPinAvailable(false);
    rc = takeSlotSummary(0, &d);
    CHECK(rc == BAD_STATE, "no-pin capture rc=0x%08X", (unsigned)rc);
    expectLog("snapshot: no view pin available - refusing the capture");
    CHECK(!g_SlotOwner[0].valid, "no pin -> no stamp");
    CHECK(g_Snapshots[0].count == 0 && g_Snapshots[0].block_size == 0,
          "no pin -> no grid (%u blocks, block size %u)",
          (unsigned)g_Snapshots[0].count, (unsigned)g_Snapshots[0].block_size);
    CHECK(nxusTestSessionOutstandingPins() == 0, "no pin was leaked (%u)",
          (unsigned)nxusTestSessionOutstandingPins());

    /* Failure before the pin: region preparation. */
    fresh();
    nxusTestSessionSetIdentity(NXUS_TEST_PID_A, NXUS_TEST_TITLE_A, 1);
    const Result prep_fail = MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    nxusTestSessionSetPrepareResult(prep_fail);
    rc = takeSlotSummary(0, &d);
    CHECK(rc == prep_fail, "prepare failure propagated rc=0x%08X (expected 0x%08X)",
          (unsigned)rc, (unsigned)prep_fail);
    CHECK(!g_SlotOwner[0].valid, "prepare failure -> no stamp");
    CHECK(g_Snapshots[0].count == 0 && g_Snapshots[0].block_size == 0,
          "prepare failure -> no grid (%u blocks, block size %u)",
          (unsigned)g_Snapshots[0].count, (unsigned)g_Snapshots[0].block_size);
    CHECK(nxusTestSessionReads() == 0, "prepare failure reads no memory (%u reads)",
          (unsigned)nxusTestSessionReads());
    CHECK(nxusTestSessionOutstandingPins() == 0, "prepare failure takes no pin (%u)",
          (unsigned)nxusTestSessionOutstandingPins());
}

/* ---- nxusSnapshotDiffMatchesCurrent() ----------------------------------- */

static void testDiffMatchesCurrentContract(void) {
    printf("[test] DiffMatchesCurrent tracks exactly the cached changed list\n");
    fresh();
    CHECK(nxusSnapshotDiffMatchesCurrent(), "no captures, no diff -> true");

    nxusTestSessionSetIdentity(NXUS_TEST_PID_A, NXUS_TEST_TITLE_A, 1);
    memset(memory(), 0x01, REGION_SIZE);
    CHECK(R_SUCCEEDED(takeSlot(0)), "capture A");
    CHECK(R_SUCCEEDED(takeSlot(1)), "capture B");
    CHECK(nxusSnapshotDiffMatchesCurrent(), "captures without a diff -> true");

    NxusSnapshotSummary d;
    Result rc = compareSlots(0, 1, &d);
    CHECK(R_SUCCEEDED(rc) && d.changed_count == 0, "empty diff rc=0x%08X changed=%u",
          (unsigned)rc, (unsigned)d.changed_count);
    CHECK(nxusSnapshotDiffMatchesCurrent(), "an empty diff is servable");

    nxusTestSessionSetIdentity(NXUS_TEST_PID_B, NXUS_TEST_TITLE_B, 2);
    CHECK(nxusSnapshotDiffMatchesCurrent(),
          "a diff with no cached rows has nothing to go stale");
    CHECK(pageAll() == 0, "no rows to page");

    /* A diff that actually cached rows. */
    fresh();
    nxusTestSessionSetIdentity(NXUS_TEST_PID_A, NXUS_TEST_TITLE_A, 1);
    memset(memory(), 0x01, REGION_SIZE);
    CHECK(R_SUCCEEDED(takeSlot(0)), "capture A");
    memory()[0x4000] ^= 0xAA;
    CHECK(R_SUCCEEDED(takeSlot(1)), "capture B");
    rc = compareSlots(0, 1, &d);
    CHECK(R_SUCCEEDED(rc), "one-change diff rc=0x%08X", (unsigned)rc);
    CHECK(d.changed_count == 1, "changed=%u", (unsigned)d.changed_count);
    CHECK(nxusSnapshotDiffMatchesCurrent(), "the diff is servable on its target");
    NxusChangedBlockWire row;
    memset(&row, 0, sizeof(row));
    CHECK(nxusSnapshotGetChanged(&row, 1, 0) == 1 &&
          row.address == NXUS_TEST_REGION_BASE + 0x4000,
          "the cached row is pageable (%llx)", (unsigned long long)row.address);

    nxusTestSessionSetIdentity(NXUS_TEST_PID_B, NXUS_TEST_TITLE_B, 2);
    CHECK(!nxusSnapshotDiffMatchesCurrent(), "cached rows of the old target -> false");
    CHECK(pageAll() == 0, "a stale diff pages no rows");
    CHECK(nxusSnapshotGetChanged(&row, 1, 0) == 0,
          "a direct page after the move is refused too");

    nxusTestSessionSetIdentity(NXUS_TEST_PID_A, NXUS_TEST_TITLE_A, 1);
    CHECK(nxusSnapshotDiffMatchesCurrent(), "back on the target -> true again");
    CHECK(pageAll() == 1, "the cached row is servable again");

    /* Any new capture ends the diff (even on another target). */
    nxusTestSessionSetIdentity(NXUS_TEST_PID_B, NXUS_TEST_TITLE_B, 2);
    CHECK(R_SUCCEEDED(takeSlot(0)), "capture A on the new target");
    CHECK(g_ChangedCount == 0 && !g_DiffOwner.valid, "a take clears the cached diff");
    CHECK(nxusSnapshotDiffMatchesCurrent(), "nothing cached -> true");
    CHECK(pageAll() == 0, "the old rows are gone");
}

/* ---- argument validation and empty state -------------------------------- */

static void testArgumentValidation(void) {
    printf("[test] out-of-range slots and empty paging are refused\n");
    fresh();
    NxusSnapshotSummary d;
    CHECK(takeSlot(2) == BAD_STATE, "capture into slot 2 is refused");
    CHECK(compareSlots(0, 2, &d) == BAD_STATE, "diff to slot 2 is refused");
    CHECK(compareSlots(2, 0, &d) == BAD_STATE, "diff from slot 2 is refused");

    NxusChangedBlockWire rows[4];
    memset(rows, 0, sizeof(rows));
    CHECK(nxusSnapshotGetChanged(NULL, 4, 0) == 0, "NULL output pages nothing");
    CHECK(nxusSnapshotGetChanged(rows, 4, 0) == 0, "no cached diff pages nothing");
    CHECK(nxusSnapshotGetChanged(rows, 0, 0) == 0, "zero max_entries pages nothing");

    NxusSnapshotSummary s;
    nxusSnapshotGetSummary(0, &s);
    CHECK(s.block_size == 0 && s.block_count == 0,
          "an untouched slot summary is empty (grid %u, blocks %u)",
          (unsigned)s.block_size, (unsigned)s.block_count);
}

/* ---- main --------------------------------------------------------------- */

int main(void) {
    printf("=== snapshot service target-owner tests ===\n");

    Result rc = nxusSnapshotServiceInit();
    CHECK(rc == 0, "service init rc=0x%08X", (unsigned)rc);
    if (rc != 0) {
        printf("=== %d checks, %d failures ===\n", g_checks, g_failures);
        return 1;
    }

    testSameTargetDiffSucceeds();
    testTitleSwitchRefused();
    testRelaunchAndCurrentTargetMoves();
    testSamePidRules();
    testUnknownPidUsesGeneration();
    testReleaseAllDropsStamps();
    testFailedCaptureLeavesNoStamp();
    testDiffMatchesCurrentContract();
    testArgumentValidation();

    nxusSnapshotReleaseAll();

    printf("=== %d checks, %d failures ===\n", g_checks, g_failures);
    if (g_failures == 0) printf("ALL SNAPSHOT-OWNER TESTS PASSED\n");
    else printf("SNAPSHOT-OWNER TESTS FAILED\n");
    return g_failures == 0 ? 0 : 1;
}
