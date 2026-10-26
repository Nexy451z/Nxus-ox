#include "nxus_snapshot_srv.h"

#include "nxus_dmntcht.h"
#include "nxus_log.h"
#include "nxus_session.h"

#include <stdlib.h>
#include <string.h>

static NxusSnapshot       g_Snapshots[2];
static u64               *g_Hashes[2];
static u64               *g_Addresses[2];
static NxusChangedBlock  *g_Changed;
static u32                g_ChangedCount;   /* last diff: cached changed blocks */
static u32                g_DiffTruncated;  /* last diff: list/slot was truncated */
static u32                g_BlockSize = NXUS_SNAPSHOT_DEFAULT_BLOCK_SIZE;
/* Per slot: that slot's *capture* ran out of blocks.  Kept apart from the diff
   flags so a capture reply never carries the previous diff's "truncated", and so
   an incomplete slot still makes a later diff report truncated=1 even when the
   changed list itself fits. */
static u32                g_SlotTruncated[2];

/*
 * Which target each slot's capture describes (and which target the cached diff
 * was computed for).
 *
 * A snapshot is nothing but per-block hashes of one process's memory, so a diff
 * is only meaningful while both slots still describe the SAME process.  Without
 * such a stamp, switching titles between the two captures still produced a
 * successful "N changed": the reply compared two unrelated address spaces, and
 * every address in the changed list pointed into whichever process was attached
 * when the diff ran.  The stamp is taken from the session inside
 * nxusSnapshotTake() - the same identity the capture reads through
 * (nxusSessionProcessId / ProgramId / Id) plus the dmnt target incarnation
 * (nxusDmntTargetIncarnation, the one token a fixed-layout restart changes) - and
 * is only published when the take succeeded.
 *
 * "Same target" follows the rule nxusSessionHitsMatchTarget() / ptrChainOwnerCheck()
 * use, so an explicit DebugAttach (program id unknown = 0) does not turn every
 * comparison into a mismatch:
 *   - the dmnt target INCARNATION (nxusDmntTargetIncarnation) must be equal on both
 *     sides.  It is the strongest token and is compared on its own: a title
 *     restarted into a FIXED layout comes back with the SAME pid, the same title id
 *     and the same mappings, so every block hash below still lines up - against
 *     another process.  A bumped incarnation is therefore a different target
 *     whatever the pid/title say,
 *   - both sides know a pid -> the pid must match, and so must the program id
 *     once both know one (a new pid is a relaunch, a new title id is a title
 *     switch),
 *   - a pid is unknown on either side -> the session generation is the only
 *     token left, exactly like the hit-list owner check.
 */
typedef struct {
    u64  pid;
    u64  program_id;
    u32  session_id;
    u32  incarnation;   /* dmnt cheat-process generation (nxusDmntTargetIncarnation) */
    bool valid;
} NxusSnapshotOwner;

static NxusSnapshotOwner g_SlotOwner[2];
/* Owner of the cached changed-block list (equal to both slots' owner: the diff
   only runs once A and B were proven to describe the same target). */
static NxusSnapshotOwner g_DiffOwner;

/* The identity the session holds RIGHT NOW. */
static NxusSnapshotOwner snapshotOwnerCurrent(void) {
    NxusSnapshotOwner owner;
    owner.pid         = nxusSessionProcessId();
    owner.program_id  = nxusSessionProgramId();
    owner.session_id  = nxusSessionId();
    owner.incarnation = nxusDmntTargetIncarnation();
    owner.valid       = true;
    return owner;
}

/* Do two stamps describe the same target?  See the block comment above. */
static bool snapshotOwnerSame(const NxusSnapshotOwner *a, const NxusSnapshotOwner *b) {
    if (!a->valid || !b->valid) return false;
    /* First, and unconditionally: the incarnation is the only token that separates
       two processes with the same pid and title id (a restart in a fixed layout).
       It also covers the no-pid fallback, where the session generation alone would
       not notice such a restart. */
    if (a->incarnation != b->incarnation) return false;
    if (a->pid != 0 && b->pid != 0) {
        if (a->pid != b->pid) return false;
        return a->program_id == 0 || b->program_id == 0 ||
               a->program_id == b->program_id;
    }
    return a->session_id == b->session_id;
}

static bool snapshotOwnerMatchesCurrent(const NxusSnapshotOwner *owner) {
    const NxusSnapshotOwner now = snapshotOwnerCurrent();
    return snapshotOwnerSame(owner, &now);
}

static void snapshotOwnerClear(u32 slot) {
    memset(&g_SlotOwner[slot], 0, sizeof(g_SlotOwner[slot]));
}

/* Slots are allocated on first use: two slots x two arrays of u64 hashes and
   addresses would otherwise reserve 2 MB of the 8 MB inner heap from boot, even
   in a session that only scans. */
static void snapshotSlotEnsure(u32 slot) {
    if (g_Snapshots[slot].hashes != NULL) return;
    g_Hashes[slot] = (u64 *)calloc(NXUS_SNAPSHOT_MAX_BLOCKS, sizeof(u64));
    g_Addresses[slot] = (u64 *)calloc(NXUS_SNAPSHOT_MAX_BLOCKS, sizeof(u64));
    if (g_Hashes[slot] == NULL || g_Addresses[slot] == NULL) {
        free(g_Hashes[slot]);
        free(g_Addresses[slot]);
        g_Hashes[slot] = NULL;
        g_Addresses[slot] = NULL;
        NXUS_LOG("snapshot: out of memory for slot %u", (unsigned)slot);
        return;
    }
    nxusSnapshotInit(&g_Snapshots[slot], g_Hashes[slot], g_Addresses[slot],
                     NXUS_SNAPSHOT_MAX_BLOCKS, g_BlockSize);
    NXUS_LOG("snapshot: slot %u allocated (%u blocks)", (unsigned)slot,
             (unsigned)NXUS_SNAPSHOT_MAX_BLOCKS);
}

/* Bytes one slot's hash + address arrays occupy while they are allocated. */
#define NXUS_SNAPSHOT_SLOT_BYTES (2ull * (u64)NXUS_SNAPSHOT_MAX_BLOCKS * (u64)sizeof(u64))

/* Is `slot` holding its arrays right now?  Both the struct (which points at them)
   and the owner pointers are checked: a slot is only "resident" when the storage
   exists for the capture/diff code to use. */
static bool snapshotSlotResident(u32 slot) {
    return g_Hashes[slot] != NULL || g_Addresses[slot] != NULL ||
           g_Snapshots[slot].hashes != NULL || g_Snapshots[slot].addresses != NULL;
}

/*
 * Reset a slot to exactly the state a never-used one has: no block grid
 * (block_size 0), no blocks, no regions.  The hash/address buffers are NOT
 * touched here - that is snapshotSlotFree() below.
 *
 * This is what makes "the take failed" distinguishable from "a capture that
 * found zero blocks": the old code only left count 0 behind, so a failed
 * capture still looked valid and nxusSnapshotCompare() reported every block of
 * the other slot as vanished (a confident "N changed" for a comparison that
 * never happened).
 *
 * The target stamp goes with the grid: a slot with no capture must not keep
 * claiming it was taken on the target the previous capture saw, or a diff could
 * accept a *new* capture next to a slot that no longer holds anything.
 */
static void snapshotSlotInvalidate(u32 slot) {
    g_Snapshots[slot].count = 0;
    g_Snapshots[slot].region_count = 0;
    g_Snapshots[slot].block_size = 0;
    g_SlotTruncated[slot] = 0;
    snapshotOwnerClear(slot);
}

/*
 * Give one slot's arrays back to the allocator and leave the slot in the exact
 * state a never-used one has, so the next capture re-allocates through the same
 * snapshotSlotEnsure() path that the first capture uses (it keys on
 * NxusSnapshot.hashes).
 *
 * The invalidate runs FIRST: block_size 0 and count 0 mean no diff and no paging
 * can reach the storage while it is being freed, and nxusSnapshotCompare() sees
 * hashes == NULL afterwards and refuses the comparison instead of diffing freed
 * memory.
 *
 * No capture can be in flight here: captures run on the connection thread and the
 * server serialises commands (and refuses SnapshotCapture while the pointer scan
 * worker runs), so the only references to the arrays are the ones freed below.
 */
static void snapshotSlotFree(u32 slot) {
    snapshotSlotInvalidate(slot);
    free(g_Hashes[slot]);
    free(g_Addresses[slot]);
    g_Hashes[slot] = NULL;
    g_Addresses[slot] = NULL;
    memset(&g_Snapshots[slot], 0, sizeof(g_Snapshots[slot]));
}

/* Release both slots - this really frees the arrays (2 x 256 KiB once both slots
   have been captured), so a release returns the memory to the 8 MB inner heap
   instead of only dropping the bookkeeping for memory that stays resident.  The
   server's heap-budget estimate asks nxusSnapshotResidentBytes() so its charge and
   the actual resident bytes can never drift apart again.
 *
 * The next capture re-allocates on demand (snapshotSlotEnsure()); nothing else has
 * to be reset. */
void nxusSnapshotReleaseAll(void) {
    u64 returned = 0;
    for (u32 slot = 0; slot < 2; slot++) {
        if (snapshotSlotResident(slot)) returned += NXUS_SNAPSHOT_SLOT_BYTES;
        snapshotSlotFree(slot);   /* also drops the slot's target stamp */
    }
    g_ChangedCount = 0;
    g_DiffTruncated = 0;
    /* The cached diff described the released captures, so its owner stamp has to
       go with them: GetChanged() must not page rows of a diff that no longer has
       a pair of captures behind it. */
    memset(&g_DiffOwner, 0, sizeof(g_DiffOwner));
    NXUS_LOG("snapshot: both slots released (%llu B returned to the heap, "
             "re-allocated by the next capture)", (unsigned long long)returned);
}

u32 nxusSnapshotResidentSlots(void) {
    u32 mask = 0;
    for (u32 slot = 0; slot < 2; slot++) {
        if (snapshotSlotResident(slot)) mask |= (1u << slot);
    }
    return mask;
}

u64 nxusSnapshotResidentBytes(void) {
    u64 bytes = 0;
    for (u32 slot = 0; slot < 2; slot++) {
        if (snapshotSlotResident(slot)) bytes += NXUS_SNAPSHOT_SLOT_BYTES;
    }
    return bytes;
}

Result nxusSnapshotServiceInit(void) {
    /* Called again on re-init: only the first call allocates, otherwise the
       previous buffer would leak (its pointer is overwritten). */
    if (g_Changed == NULL) {
        g_Changed = (NxusChangedBlock *)calloc(NXUS_SNAPSHOT_MAX_CHANGED, sizeof(NxusChangedBlock));
        if (g_Changed == NULL) return MAKERESULT(Module_Libnx, LibnxError_OutOfMemory);
    }
    NXUS_LOG("snapshot: %u blocks max, default block %u bytes, slots lazily allocated",
             (unsigned)NXUS_SNAPSHOT_MAX_BLOCKS, (unsigned)g_BlockSize);
    return 0;
}

Result nxusSnapshotTake(u32 slot, u32 scope, u64 range_begin, u64 range_end,
                        u32 block_size, NxusSnapshotSummary *out) {
    if (slot > 1) return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE);

    /* A capture ends the life of the previous diff: its changed_count must not
       leak into this capture's summary (the GUI printed "N changed" with an
       empty list) and SnapshotChanged must not page rows of a diff that no
       longer belongs to the slots as captured now.  The diff's target stamp goes
       with it - a new capture starts a new pair. */
    g_ChangedCount = 0;
    g_DiffTruncated = 0;
    memset(&g_DiffOwner, 0, sizeof(g_DiffOwner));

    snapshotSlotEnsure(slot);
    if (g_Snapshots[slot].hashes == NULL) return MAKERESULT(Module_Libnx, LibnxError_OutOfMemory);

    /* From here on the slot is "captured" only if this take completes: clear it
       first, so every early failure below (region prepare, token pin, malloc)
       leaves an uncaptured slot instead of the previous - possibly unrelated -
       capture, or an empty grid that diffs as "everything vanished". */
    snapshotSlotInvalidate(slot);

    if (block_size == 0) block_size = NXUS_SNAPSHOT_DEFAULT_BLOCK_SIZE;
    if (block_size < 256) block_size = 256;
    /* A block is hashed from one read of at most chunk_size bytes, so a block
       larger than the chunk would silently miss everything past the chunk. */
    if (block_size > 64u * 1024u) block_size = 64u * 1024u;
    block_size = (block_size + 0xFFu) & ~0xFFu;

    Result rc = nxusSessionPrepareRegions(scope, range_begin, range_end);
    if (R_FAILED(rc)) return rc;

    /* Token pin: the capture below walks the region list for its whole duration,
       so the pin must cover it and only this function can drop it.  Every early
       return from here on unpins. */
    NxusViewPin pin;
    if (!nxusSessionViewPinCurrent(&pin)) {
        NXUS_LOG("snapshot: no view pin available - refusing the capture");
        return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE);
    }
    u32 region_count = 0;
    const NxusScanRegion *regions = nxusSessionRegionsPinned(&pin, &region_count);

    /* The identity this capture is taken on.  Read once, BEFORE the reads, so the
       stamp names the process the hashes came from even if the 1 Hz identity tick
       attaches to another target while the capture runs.  It is published only
       when the take succeeds (see the two success paths below), never on an early
       return: an uncaptured slot carries no owner. */
    const NxusSnapshotOwner owner = snapshotOwnerCurrent();

    nxusSnapshotInit(&g_Snapshots[slot], g_Hashes[slot], g_Addresses[slot],
                     NXUS_SNAPSHOT_MAX_BLOCKS, block_size);
    g_SlotTruncated[slot] = 0;   /* this capture's own state, not the previous one's */

    /* Bigger chunk = fewer read round trips: the capture coalesces a run of
       whole blocks into one read, up to 16 of them.  1 MB would be comfortable,
       but the sysmodule only has an 8 MB inner heap (the two snapshot slots
       alone take 2 x 256 KB), so cap the scratch buffer at 256 KB. */
    const u32 chunk_size = 256 * 1024;
    u8 *chunk = (u8 *)malloc(chunk_size);
    if (chunk == NULL) {
        /* The token pin is held: drop it before bailing out, or the retire ring
           never drains and every later publish leaks its old block. */
        nxusSessionViewUnpin(&pin);
        return MAKERESULT(Module_Libnx, LibnxError_OutOfMemory);
    }

    NxusScanStats stats;
    int src = nxusSnapshotCapture(&g_Snapshots[slot], regions, region_count,
                                  nxusSessionReadCallback, NULL, chunk, chunk_size, &stats, NULL);
    /* The region list was pinned by the token above: drop it now that the capture
       is finished, or the next rebuild has to keep the old block alive. */
    nxusSessionViewUnpin(&pin);
    free(chunk);

    NXUS_LOG("snapshot %c: blocks=%u reads=%llu dropped=%u rc=%d",
             slot ? 'B' : 'A', (unsigned)g_Snapshots[slot].count,
             (unsigned long long)stats.reads, (unsigned)stats.dropped, src);

    /* A capture that hashed not a single block (every read refused, the region
       list came back empty, or it was cancelled before the first block) is not a
       snapshot: what it produces is "zero blocks", which the diff would turn into
       "every block of the other slot vanished".  Fail it here instead. */
    if (g_Snapshots[slot].count == 0) {
        snapshotSlotInvalidate(slot);
        NXUS_LOG("snapshot %c: no block could be captured - slot %c left uncaptured",
                 slot ? 'B' : 'A', slot ? 'B' : 'A');
        return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE);
    }

    if (src == NXUS_SNAPSHOT_ERR_FULL) {
        /* The block table filled up.  The blocks captured so far are still valid,
           so report them with truncated=1 (the client can retry with a larger
           block size) instead of discarding a snapshot the user waited for. */
        g_BlockSize = block_size;
        g_SlotTruncated[slot] = 1;
        g_SlotOwner[slot] = owner;   /* partial, but still this target's blocks */
        nxusSnapshotGetSummary(slot, out);
        NXUS_LOG("snapshot %c: hit the block limit - reporting %u block(s) as truncated",
                 slot ? 'B' : 'A', (unsigned)g_Snapshots[slot].count);
        return 0;
    }
    if (src != NXUS_SNAPSHOT_OK && src != NXUS_SNAPSHOT_ERR_CANCELLED) {
        /* Nothing was vouched for: keep the slot uncaptured (block_size 0), so a
           later diff returns BAD_STATE instead of "N blocks vanished".  The
           engine already cleared the grid on this path; this keeps the slot
           consistent even if a future engine error appears here. */
        snapshotSlotInvalidate(slot);
        NXUS_LOG("snapshot %c: capture failed (rc=%d) - slot %c left uncaptured",
                 slot ? 'B' : 'A', src, slot ? 'B' : 'A');
        return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE);
    }

    g_BlockSize = block_size;
    /* The take is complete: the slot now describes this target, and a diff may
       use it - but only next to a slot stamped with the same identity. */
    g_SlotOwner[slot] = owner;
    NXUS_LOG("snapshot %c: captured on pid=%llu title=%016llX (session %u, incarnation %u)",
             slot ? 'B' : 'A', (unsigned long long)owner.pid,
             (unsigned long long)owner.program_id, (unsigned)owner.session_id,
             (unsigned)owner.incarnation);
    nxusSnapshotGetSummary(slot, out);
    return 0;
}

Result nxusSnapshotCompare(u32 from_slot, u32 to_slot, NxusSnapshotSummary *out) {
    if (from_slot > 1 || to_slot > 1) return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE);

    /* Whatever this comparison decides, the previous diff's rows stop being
       pageable now: a refused or failed diff leaving changed_count behind made
       SnapshotChanged hand out rectangles of a comparison the client never got a
       success reply for.  Clearing the owner stamp is part of that: a diff below
       only re-publishes it when it really ran. */
    g_ChangedCount = 0;
    g_DiffTruncated = 0;
    memset(&g_DiffOwner, 0, sizeof(g_DiffOwner));

    /* An uncaptured slot (never taken, the take failed, released by
       nxusSnapshotReleaseAll(), or not a single block could be hashed - it then has
       no block grid, block_size 0, and no blocks) cannot be compared: the diff would
       report every block of the other side as vanished, i.e. success with a
       full-size changed list for a comparison that never happened.  BAD_STATE is
       what the client can act on ("capture that slot first").  Checked before the
       NULL-array test below on purpose: a release frees the arrays AND invalidates
       the grid, and that must read as "not captured", not as "service not
       initialised". */
    const int from_valid = g_Snapshots[from_slot].block_size != 0 && g_Snapshots[from_slot].count != 0;
    const int to_valid = g_Snapshots[to_slot].block_size != 0 && g_Snapshots[to_slot].count != 0;
    if (!from_valid || !to_valid) {
        NXUS_LOG("snapshot diff %c->%c: slot %c holds no capture - refusing to compare",
                 from_slot ? 'B' : 'A', to_slot ? 'B' : 'A',
                 !from_valid ? (from_slot ? 'B' : 'A') : (to_slot ? 'B' : 'A'));
        return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE);
    }
    /* A valid grid always has its arrays (the service allocates them before
       nxusSnapshotInit() publishes the grid), so this is a defensive guard: report
       the missing storage instead of walking a NULL pointer. */
    if (g_Snapshots[from_slot].hashes == NULL || g_Snapshots[to_slot].hashes == NULL)
        return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);

    /* A diff is only meaningful between captures of the SAME process: two
       unrelated address spaces merged into one "N changed" list report success
       for a comparison that means nothing.  This is the title-switch case
       (capture A on title 1, ForceOpen title 2, capture B): both slots are
       captured and the block sizes even match, so nothing below would have
       refused it.  BAD_STATE is what the client can act on ("capture both
       again"); the log names both slots in A/B order, whatever order the client
       passed them in. */
    /* The incarnation is checked before the pid/title rule so the refusal can name
       it.  The "different targets" line below could not: both captures then carry
       the same pid AND the same title id - that is exactly what a restart into a
       fixed layout looks like - so the log would print two identical stamps and
       explain nothing. */
    if (g_SlotOwner[from_slot].valid && g_SlotOwner[to_slot].valid &&
        g_SlotOwner[from_slot].incarnation != g_SlotOwner[to_slot].incarnation) {
        NXUS_LOG("snapshot: slots were captured in different target incarnations "
                 "(A incarnation=%u, B incarnation=%u) - capture both again",
                 (unsigned)g_SlotOwner[0].incarnation,
                 (unsigned)g_SlotOwner[1].incarnation);
        return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE);
    }
    if (!snapshotOwnerSame(&g_SlotOwner[from_slot], &g_SlotOwner[to_slot])) {
        NXUS_LOG("snapshot: slots were captured for different targets "
                 "(A pid=%llu title=%016llX, B pid=%llu title=%016llX) - capture both again",
                 (unsigned long long)g_SlotOwner[0].pid,
                 (unsigned long long)g_SlotOwner[0].program_id,
                 (unsigned long long)g_SlotOwner[1].pid,
                 (unsigned long long)g_SlotOwner[1].program_id);
        return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE);
    }

    /* The pair also has to describe the target the session is on NOW.  A
       relaunch / re-attach / switch to a third title between the captures and the
       diff would otherwise page rectangles of a process that is gone (or, worse,
       of a new process at the same numeric addresses).  The capture keeps working
       after a scan or a Reset on the same target: the pid/title rule ignores the
       session generation while a pid is known. */
    const NxusSnapshotOwner now = snapshotOwnerCurrent();
    /* The incarnation first, and with both values in the log: a restart in a fixed
       layout keeps pid and title id, so the generic line below would print the same
       identity on both sides ("was pid=100 title=... , now pid=100 title=...") and
       leave the client guessing why its comparison was refused. */
    if (g_SlotOwner[from_slot].valid &&
        g_SlotOwner[from_slot].incarnation != now.incarnation) {
        NXUS_LOG("snapshot diff %c->%c: captures belong to an earlier dmnt target "
                 "incarnation (was %u, now %u) - capture both again",
                 from_slot ? 'B' : 'A', to_slot ? 'B' : 'A',
                 (unsigned)g_SlotOwner[from_slot].incarnation,
                 (unsigned)now.incarnation);
        return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE);
    }
    if (!snapshotOwnerMatchesCurrent(&g_SlotOwner[from_slot])) {
        NXUS_LOG("snapshot diff %c->%c: captures were taken on pid=%llu title=%016llX "
                 "but the current target is pid=%llu title=%016llX - capture both again",
                 from_slot ? 'B' : 'A', to_slot ? 'B' : 'A',
                 (unsigned long long)g_SlotOwner[from_slot].pid,
                 (unsigned long long)g_SlotOwner[from_slot].program_id,
                 (unsigned long long)now.pid, (unsigned long long)now.program_id);
        return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE);
    }

    /* An incomplete slot makes the whole comparison unreliable, even if the diff
       itself does not overflow (otherwise a truncated A looks like a clean A). */
    g_DiffTruncated = (g_SlotTruncated[from_slot] || g_SlotTruncated[to_slot]) ? 1u : 0u;

    /* Both captures have to use the same block size: the addresses are block
       positions, so a 4 KB A against a 16 KB B cannot be lined up at all.
       nxusSnapshotDiff() returns ERR_PARAM for that, and swallowing it here turned
       a comparison that never happened into "0 changed blocks, truncated=0" -
       which the CLI shows as "nothing changed".  The mock already fails this case,
       so E2E never saw the regression; refuse it on the console too. */
    if (g_Snapshots[from_slot].block_size != g_Snapshots[to_slot].block_size) {
        NXUS_LOG("snapshot diff %c(%u B) -> %c(%u B): block size mismatch - refusing to compare",
                 from_slot ? 'B' : 'A', (unsigned)g_Snapshots[from_slot].block_size,
                 to_slot ? 'B' : 'A', (unsigned)g_Snapshots[to_slot].block_size);
        return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE);
    }

    int src = nxusSnapshotDiff(&g_Snapshots[from_slot], &g_Snapshots[to_slot],
                               g_Changed, NXUS_SNAPSHOT_MAX_CHANGED, &g_ChangedCount);
    if (src == NXUS_SNAPSHOT_ERR_FULL) {
        g_DiffTruncated = 1;
    } else if (src != NXUS_SNAPSHOT_OK) {
        /* Any other engine error is a failed comparison, never an empty change
           list: propagate it instead of returning success with changed_count=0. */
        NXUS_LOG("snapshot diff %c->%c failed: engine rc=%d - propagation to the client",
                 from_slot ? 'B' : 'A', to_slot ? 'B' : 'A', src);
        g_ChangedCount = 0;
        g_DiffTruncated = 0;
        return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE);
    }

    /* The comparison ran against a pair of captures that describe one target, and
       both still match the session: the changed list may be paged for exactly this
       target from now on. */
    g_DiffOwner = g_SlotOwner[from_slot];

    NXUS_LOG("snapshot diff %c->%c: %u changed blocks%s",
             from_slot ? 'B' : 'A', to_slot ? 'B' : 'A', (unsigned)g_ChangedCount,
             g_DiffTruncated ? " (truncated)" : "");

    if (out != NULL) {
        nxusSnapshotGetSummary(to_slot, out);
        out->changed_count = g_ChangedCount;
        /* The diff reply carries the diff's own truncation plus either capture's
           incomplete block table: a truncated A must not look like a clean A. */
        out->truncated = g_DiffTruncated;
    }
    return 0;
}

/* May the cached changed-block list still be served?  See the contract in
   nxus_snapshot_srv.h and the owner block at the top of this file. */
bool nxusSnapshotDiffMatchesCurrent(void) {
    /* No cached diff: nothing can be stale, and SnapshotChanged before the first
       diff keeps its old (empty) reply instead of turning into an error. */
    if (g_ChangedCount == 0) return true;
    return snapshotOwnerMatchesCurrent(&g_DiffOwner);
}

u32 nxusSnapshotGetChanged(NxusChangedBlockWire *out, u32 max_entries, u32 offset) {
    if (out == NULL || offset >= g_ChangedCount) return 0;
    /* The cached rows are rectangles of the target the diff ran on.  Once the
       session moved elsewhere they describe the previous process's memory, so
       none of them is served: the server refuses the page with BAD_STATE (via
       nxusSnapshotDiffMatchesCurrent), and a caller that skipped that check gets
       an empty page instead of addresses it cannot trust. */
    if (!snapshotOwnerMatchesCurrent(&g_DiffOwner)) return 0;
    u32 n = g_ChangedCount - offset;
    if (n > max_entries) n = max_entries;
    for (u32 i = 0; i < n; i++) {
        const NxusChangedBlock *src = &g_Changed[offset + i];
        out[i].address = src->address;
        out[i].size = src->size;
        out[i].flags = src->reserved;
    }
    return n;
}

void nxusSnapshotGetSummary(u32 slot, NxusSnapshotSummary *out) {
    if (out == NULL || slot > 1) return;
    memset(out, 0, sizeof(*out));
    out->slot = slot;
    out->block_count = g_Snapshots[slot].count;
    out->block_size = g_Snapshots[slot].block_size;   /* 0 = slot not captured */
    out->region_count = g_Snapshots[slot].region_count;
    /* The diff columns describe the last nxusSnapshotCompare() only.  A capture
       zeroes them (nxusSnapshotTake) before it replies, so a capture summary
       never advertises the previous diff's changed_count, and neither does the
       GetSummary() the server uses for its block-size check.  'truncated' is the
       per-slot capture flag, so a capture reply says "this capture hit the block
       limit" rather than "the last diff was truncated". */
    out->changed_count = g_ChangedCount;
    out->truncated = g_SlotTruncated[slot];
}
