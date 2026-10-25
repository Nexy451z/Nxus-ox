#include "nxus_snapshot_srv.h"

#include "nxus_log.h"
#include "nxus_session.h"

#include <stdlib.h>
#include <string.h>

static NxusSnapshot       g_Snapshots[2];
static u64               *g_Hashes[2];
static u64               *g_Addresses[2];
static NxusChangedBlock  *g_Changed;
static u32                g_ChangedCount;
static u32                g_BlockSize = NXUS_SNAPSHOT_DEFAULT_BLOCK_SIZE;
static u32                g_Truncated;
/* Per slot: a capture that ran out of blocks leaves its slot incomplete, and a
   later diff involving it must not report a clean result. */
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
    snapshotSlotEnsure(slot);
    if (g_Snapshots[slot].hashes == NULL) return MAKERESULT(Module_Libnx, LibnxError_OutOfMemory);

    if (block_size == 0) block_size = NXUS_SNAPSHOT_DEFAULT_BLOCK_SIZE;
    if (block_size < 256) block_size = 256;
    /* A block is hashed from one read of at most chunk_size bytes, so a block
       larger than the chunk would silently miss everything past the chunk. */
    if (block_size > 64u * 1024u) block_size = 64u * 1024u;
    block_size = (block_size + 0xFFu) & ~0xFFu;

    Result rc = nxusSessionPrepareRegions(scope, range_begin, range_end);
    if (R_FAILED(rc)) return rc;

    u32 region_count = 0;
    const NxusScanRegion *regions = nxusSessionRegions(&region_count);

    nxusSnapshotInit(&g_Snapshots[slot], g_Hashes[slot], g_Addresses[slot],
                     NXUS_SNAPSHOT_MAX_BLOCKS, block_size);
    g_Truncated = 0;      /* this capture's own state, not the previous one's */
    g_SlotTruncated[slot] = 0;

    /* Bigger chunk = fewer read round trips: the capture coalesces a run of
       whole blocks into one read, up to 16 of them.  1 MB would be comfortable,
       but the sysmodule only has an 8 MB inner heap (the two snapshot slots
       alone take 2 x 256 KB), so cap the scratch buffer at 256 KB. */
    const u32 chunk_size = 256 * 1024;
    u8 *chunk = (u8 *)malloc(chunk_size);
    if (chunk == NULL) {
        /* The region list is pinned: release it before bailing out, or the retire
           ring never drains and every later publish leaks its old block. */
        nxusSessionViewRelease();
        return MAKERESULT(Module_Libnx, LibnxError_OutOfMemory);
    }

    NxusScanStats stats;
    int src = nxusSnapshotCapture(&g_Snapshots[slot], regions, region_count,
                                  nxusSessionReadCallback, NULL, chunk, chunk_size, &stats, NULL);
    /* The region list was pinned by nxusSessionRegions(): drop it now that the
       capture is finished, or the next rebuild has to keep the old block alive. */
    nxusSessionViewRelease();
    free(chunk);

    NXUS_LOG("snapshot %c: blocks=%u reads=%llu dropped=%u rc=%d",
             slot ? 'B' : 'A', (unsigned)g_Snapshots[slot].count,
             (unsigned long long)stats.reads, (unsigned)stats.dropped, src);

    if (src == NXUS_SNAPSHOT_ERR_FULL) {
        /* The block table filled up.  The blocks captured so far are still valid,
           so report them with truncated=1 (the client can retry with a larger
           block size) instead of discarding a snapshot the user waited for. */
        g_BlockSize = block_size;
        g_Truncated = 1;
        g_SlotTruncated[slot] = 1;
        nxusSnapshotGetSummary(slot, out);
        NXUS_LOG("snapshot %c: hit the block limit - reporting %u block(s) as truncated",
                 slot ? 'B' : 'A', (unsigned)g_Snapshots[slot].count);
        return 0;
    }
    if (src != NXUS_SNAPSHOT_OK && src != NXUS_SNAPSHOT_ERR_CANCELLED) {
        return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE);
    }

    g_BlockSize = block_size;
    nxusSnapshotGetSummary(slot, out);
    return 0;
}

Result nxusSnapshotCompare(u32 from_slot, u32 to_slot, NxusSnapshotSummary *out) {
    if (from_slot > 1 || to_slot > 1) return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE);
    if (g_Snapshots[from_slot].hashes == NULL || g_Snapshots[to_slot].hashes == NULL)
        return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);

    g_ChangedCount = 0;
    /* An incomplete slot makes the whole comparison unreliable, even if the diff
       itself does not overflow (otherwise a truncated A looks like a clean A). */
    g_Truncated = (g_SlotTruncated[from_slot] || g_SlotTruncated[to_slot]) ? 1u : 0u;

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
        g_Truncated = 1;
    } else if (src != NXUS_SNAPSHOT_OK) {
        /* Any other engine error is a failed comparison, never an empty change
           list: propagate it instead of returning success with changed_count=0. */
        NXUS_LOG("snapshot diff %c->%c failed: engine rc=%d - propagation to the client",
                 from_slot ? 'B' : 'A', to_slot ? 'B' : 'A', src);
        g_ChangedCount = 0;
        return (Result)NXUS_MAKE_RESULT(NXUS_ERR_BAD_STATE);
    }

    NXUS_LOG("snapshot diff %c->%c: %u changed blocks%s",
             from_slot ? 'B' : 'A', to_slot ? 'B' : 'A', (unsigned)g_ChangedCount,
             g_Truncated ? " (truncated)" : "");

    if (out != NULL) {
        nxusSnapshotGetSummary(to_slot, out);
        out->changed_count = g_ChangedCount;
        out->truncated = g_Truncated;
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
    out->block_size = g_Snapshots[slot].block_size;
    out->region_count = g_Snapshots[slot].region_count;
    out->changed_count = g_ChangedCount;
    out->truncated = g_Truncated;
}
