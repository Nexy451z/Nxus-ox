/*
 * Nxus memory snapshots (portable core).
 *
 * The old workflow dumped hundreds of megabytes to the PC and diffed them
 * there.  Nxus keeps a *fixed-size hash per block* on the console instead
 * (520MB of heap costs ~1MB of hashes at 4KB blocks), so a diff needs no dump
 * at all: capture, let the game run, capture again, ask which blocks changed,
 * then pull only those blocks.
 *
 * This also gives the "unknown initial value" search for free: whatever moved
 * while you played is exactly what a value search would have narrowed to.
 */
#pragma once

#include "nxus_scan.h"

/*
 * Sizing for the console: two snapshots (A/B) keep hashes *and* block addresses,
 * and the slot arrays are allocated on first use rather than at boot.
 * 16384 blocks x the 16 KB default covers 256 MB of target memory, which is more
 * than any single module plus heap; each slot costs 2 * 16384 * 8B = 256 KB.
 * A capture that runs out of blocks reports 'truncated' with the partial result
 * instead of throwing the snapshot away, and blocks are clamped to the 64 KB read
 * chunk so no part of a block is silently left unhashed.
 */
#define NXUS_SNAPSHOT_MAX_BLOCKS (16u * 1024u)
#define NXUS_SNAPSHOT_DEFAULT_BLOCK_SIZE 16384u
#define NXUS_SNAPSHOT_MAX_CHANGED (16u * 1024u)

/*
 * NOTE: the struct only *points at* caller-owned storage.  Copying it aliases
 * that storage, so two snapshots must always be given different buffers (the
 * sysmodule keeps an A/B pair).
 */
typedef struct {
    u64 *hashes;       /* caller-provided storage: capacity entries */
    u64 *addresses;    /* caller-provided storage: capacity entries */
    u32  count;
    u32  capacity;
    u32  block_size;
    u32  region_count;
} NxusSnapshot;

typedef struct {
    u64 address;
    u32 size;
    u32 reserved;
} NxusChangedBlock;

#define NXUS_SNAPSHOT_OK            0
#define NXUS_SNAPSHOT_ERR_PARAM    (-1)
#define NXUS_SNAPSHOT_ERR_FULL     (-2)
#define NXUS_SNAPSHOT_ERR_CANCELLED (-3)

/* FNV-1a 64 bit: fast, dependency free, good enough to detect changed blocks. */
u64 nxusHash64(const u8 *data, u32 size);

void nxusSnapshotInit(NxusSnapshot *snapshot, u64 *hash_storage, u64 *address_storage,
                      u32 capacity, u32 block_size);

/* Walk the regions in order and hash every aligned block. */
int nxusSnapshotCapture(NxusSnapshot *snapshot, const NxusScanRegion *regions, u32 region_count,
                        NxusReadFn read, void *read_ctx,
                        u8 *chunk, u32 chunk_size,
                        NxusScanStats *stats, int *cancel);

/*
 * Compare two snapshots taken with the same block size.  Both address arrays are
 * ascending (capture walks the regions in order), so this is a merge.  Blocks
 * that only exist in one of the snapshots are reported as changed.
 */
int nxusSnapshotDiff(const NxusSnapshot *from, const NxusSnapshot *to,
                     NxusChangedBlock *out, u32 max_out, u32 *out_count);
