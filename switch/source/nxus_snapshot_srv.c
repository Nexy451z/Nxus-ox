#include "nxus_snapshot_srv.h"

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

/*
 * Reset a slot to exactly the state a never-used one has: no block grid
 * (block_size 0), no blocks, no regions.  The hash/address buffers stay
 * allocated - the server counts them against the heap budget once the slot is
 * first used - but there is no capture to diff any more.
 *
 * This is what makes "the take failed" distinguishable from "a capture that
 * found zero blocks": the old code only left count 0 behind, so a failed
 * capture still looked valid and nxusSnapshotCompare() reported every block of
 * the other slot as vanished (a confident "N changed" for a comparison that
 * never happened).
 */
static void snapshotSlotInvalidate(u32 slot) {
    g_Snapshots[slot].count = 0;
    g_Snapshots[slot].region_count = 0;
    g_Snapshots[slot].block_size = 0;
    g_SlotTruncated[slot] = 0;
}

/* Release both slots.  The service is the only owner of the validity marker, so
   the server must not try to fake a release through nxusSnapshotTake(): the clean
   call keeps the invalidation rule in one place. */
void nxusSnapshotReleaseAll(void) {
    for (u32 slot = 0; slot < 2; slot++) snapshotSlotInvalidate(slot);
    g_ChangedCount = 0;
    g_DiffTruncated = 0;
    NXUS_LOG("snapshot: both slots released");
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
       longer belongs to the slots as captured now. */
    g_ChangedCount = 0;
    g_DiffTruncated = 0;

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
    nxusSnapshotGetSummary(slot, out);
    return 0;
}

Result nxusSnapshotCompare(u32 from_slot, u32 to_slot, NxusSnapshotSummary *out) {
    if (from_slot > 1 || to_slot > 1) return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE);

    /* Whatever this comparison decides, the previous diff's rows stop being
       pageable now: a refused or failed diff leaving changed_count behind made
       SnapshotChanged hand out rectangles of a comparison the client never got a
       success reply for. */
    g_ChangedCount = 0;
    g_DiffTruncated = 0;

    if (g_Snapshots[from_slot].hashes == NULL || g_Snapshots[to_slot].hashes == NULL)
        return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);

    /* An uncaptured slot (never taken, the take failed, or not a single block
       could be hashed - it then has no block grid, block_size 0, and no blocks)
       cannot be compared: the diff would report every block of the other side as
       vanished, i.e. success with a full-size changed list for a comparison that
       never happened.  BAD_STATE is what the client can act on ("capture that
       slot first"). */
    const int from_valid = g_Snapshots[from_slot].block_size != 0 && g_Snapshots[from_slot].count != 0;
    const int to_valid = g_Snapshots[to_slot].block_size != 0 && g_Snapshots[to_slot].count != 0;
    if (!from_valid || !to_valid) {
        NXUS_LOG("snapshot diff %c->%c: slot %c holds no capture - refusing to compare",
                 from_slot ? 'B' : 'A', to_slot ? 'B' : 'A',
                 !from_valid ? (from_slot ? 'B' : 'A') : (to_slot ? 'B' : 'A'));
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

u32 nxusSnapshotGetChanged(NxusChangedBlockWire *out, u32 max_entries, u32 offset) {
    if (out == NULL || offset >= g_ChangedCount) return 0;
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
