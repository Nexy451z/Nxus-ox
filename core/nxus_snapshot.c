#include "nxus_snapshot.h"

#include <string.h>

/*
 * Blocks coalesced into a single read() when the caller's chunk buffer is at
 * least block_size * NXUS_SNAPSHOT_BATCH_BLOCKS.  16 matches the sysmodule's
 * 256 KB chunk over the 16 KB default block.  The gate is deliberately in
 * blocks rather than "whatever fits": callers with a small chunk (the host
 * tests use four blocks) keep the plain one-read-per-block path.
 */
#define NXUS_SNAPSHOT_BATCH_BLOCKS 16u

u64 nxusHash64(const u8 *data, u32 size) {
    u64 hash = 0xCBF29CE484222325ull;      /* FNV offset basis */
    for (u32 i = 0; i < size; i++) {
        hash ^= (u64)data[i];
        hash *= 0x100000001B3ull;          /* FNV prime */
    }
    return hash;
}

void nxusSnapshotInit(NxusSnapshot *snapshot, u64 *hash_storage, u64 *address_storage,
                      u32 capacity, u32 block_size) {
    if (snapshot == NULL) return;
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->hashes = hash_storage;
    snapshot->addresses = address_storage;
    snapshot->capacity = capacity;
    snapshot->block_size = block_size ? block_size : NXUS_SNAPSHOT_DEFAULT_BLOCK_SIZE;
}

/*
 * A capture that failed must not leave the slot looking like a valid capture of
 * zero blocks.  nxusSnapshotDiff() reports every block that only exists on one
 * side, so a zero-block "valid" snapshot turns "this slot was never captured"
 * into "every block of the other side vanished" - a convincing N-changed result
 * that never happened.  block_size is the validity marker (nxusSnapshotInit()
 * never stores 0, and a capture always picks a non-zero block size), so an
 * invalidated snapshot has no block grid at all and the diff refuses it.
 */
static void nxusSnapshotMarkInvalid(NxusSnapshot *snapshot) {
    snapshot->count = 0;
    snapshot->region_count = 0;
    snapshot->block_size = 0;
}

int nxusSnapshotCapture(NxusSnapshot *snapshot, const NxusScanRegion *regions, u32 region_count,
                        NxusReadFn read, void *read_ctx,
                        u8 *chunk, u32 chunk_size,
                        NxusScanStats *stats, int *cancel) {
    /* Zero the caller's counters before anything else: the early PARAM returns
       below must not leave uninitialised stats behind for the caller to read. */
    if (stats != NULL) memset(stats, 0, sizeof(*stats));

    if (snapshot == NULL) return NXUS_SNAPSHOT_ERR_PARAM;
    if (regions == NULL || read == NULL || chunk == NULL ||
        snapshot->hashes == NULL || snapshot->addresses == NULL || chunk_size < 16) {
        /* The capture never started, so not a single block of the previous
           content can be vouched for: drop it instead of keeping a stale grid
           that a later diff would happily use. */
        nxusSnapshotMarkInvalid(snapshot);
        return NXUS_SNAPSHOT_ERR_PARAM;
    }
    /* block_size 0 means "nothing captured" (see above): there is no grid to
       walk.  Leave it invalid rather than inventing one. */
    if (snapshot->block_size == 0) return NXUS_SNAPSHOT_ERR_PARAM;

    /* From here the walk only stops on FULL (the block table filled up) or
       CANCELLED.  Both are partial snapshots whose already-hashed blocks are
       real, so neither invalidates the grid: the caller reports FULL as
       truncated and CANCELLED as a cancelled capture. */
    snapshot->count = 0;
    snapshot->region_count = region_count;

    const u32 block_size = snapshot->block_size;
    /* One read() may cover up to this many blocks; 1 means "no coalescing". */
    const u32 batch_limit =
        ((u64)chunk_size >= (u64)block_size * NXUS_SNAPSHOT_BATCH_BLOCKS)
            ? NXUS_SNAPSHOT_BATCH_BLOCKS : 1u;

    u64 total_bytes = 0;
    for (u32 r = 0; r < region_count; r++) total_bytes += regions[r].size;

    if (stats != NULL) stats->regions_total = region_count;

    /* Read aligned to the block grid, even when a region starts mid-block. */
    for (u32 r = 0; r < region_count; r++) {
        const u64 region_start = regions[r].base;
        const u64 region_end = regions[r].base + regions[r].size;

        u64 block = region_start - (region_start % block_size);
        while (block < region_end) {
            if (cancel != NULL && *cancel) {
                if (stats != NULL) stats->regions_done = r;
                return NXUS_SNAPSHOT_ERR_CANCELLED;
            }

            u64 read_start = block;
            u32 read_size = block_size;
            if (read_start < region_start) read_size -= (u32)(region_start - read_start);
            if (read_start + read_size > region_end) read_size = (u32)(region_end - read_start);
            if (read_size == 0) { block += block_size; continue; }
            if (read_size > chunk_size) read_size = chunk_size;

            /*
             * Coalesce a run of whole blocks into one read(): the addresses and
             * hashes produced are byte-for-byte the same as the per-block loop,
             * only the number of round trips drops.  A short first/last block,
             * a block larger than the chunk, or a too-small chunk keeps the
             * single-block path.
             */
            u32 span_blocks = 1;
            if (batch_limit > 1 && read_size == block_size) {
                const u64 full_left = (region_end - read_start) / block_size;
                const u32 room = (snapshot->count < snapshot->capacity)
                                     ? snapshot->capacity - snapshot->count : 0;
                span_blocks = batch_limit;
                if ((u64)span_blocks > full_left) span_blocks = (u32)full_left;
                if (span_blocks > room) span_blocks = room;
                if (span_blocks < 2) span_blocks = 1;
            }

            if (span_blocks > 1) {
                const u32 span = span_blocks * block_size;
                if (read(read_ctx, read_start, chunk, span) == 0) {
                    for (u32 i = 0; i < span_blocks; i++) {
                        if (snapshot->count >= snapshot->capacity) {
                            return NXUS_SNAPSHOT_ERR_FULL;
                        }
                        snapshot->hashes[snapshot->count] =
                            nxusHash64(chunk + (u64)i * block_size, block_size);
                        snapshot->addresses[snapshot->count] = read_start + (u64)i * block_size;
                        snapshot->count++;
                    }
                    if (stats != NULL) {
                        stats->reads++;
                        stats->bytes_read += span;
                        stats->bytes_scanned += span;
                        if (total_bytes) stats->permille = (u32)((stats->bytes_scanned * 1000ull) / total_bytes);
                    }
                    block += (u64)span_blocks * block_size;
                    continue;
                }
                /* The coalesced read was refused: fall back to the exact
                   one-block sequence (behaviour and stats included) below. */
            }

            if (read(read_ctx, read_start, chunk, read_size) != 0) {
                if (stats != NULL) {
                    stats->dropped++;
                    stats->bytes_scanned += read_size;
                    if (total_bytes) stats->permille = (u32)((stats->bytes_scanned * 1000ull) / total_bytes);
                }
                block += block_size;
                continue;
            }

            if (snapshot->count >= snapshot->capacity) {
                return NXUS_SNAPSHOT_ERR_FULL;
            }
            snapshot->hashes[snapshot->count] = nxusHash64(chunk, read_size);
            snapshot->addresses[snapshot->count] = block;
            snapshot->count++;

            if (stats != NULL) {
                stats->reads++;
                stats->bytes_read += read_size;
                stats->bytes_scanned += read_size;
                if (total_bytes) stats->permille = (u32)((stats->bytes_scanned * 1000ull) / total_bytes);
            }

            block += block_size;
        }
        if (stats != NULL) stats->regions_done = r + 1;
    }

    return NXUS_SNAPSHOT_OK;
}

int nxusSnapshotDiff(const NxusSnapshot *from, const NxusSnapshot *to,
                     NxusChangedBlock *out, u32 max_out, u32 *out_count) {
    if (from == NULL || to == NULL || out == NULL || out_count == NULL) return NXUS_SNAPSHOT_ERR_PARAM;
    /* block_size 0 = a capture that never completed (or a slot that was never
       captured): there is no block grid to merge against, and treating it as
       "zero blocks" would report the whole other side as vanished.  Refuse. */
    if (from->block_size == 0 || to->block_size == 0) return NXUS_SNAPSHOT_ERR_PARAM;
    if (from->block_size != to->block_size) return NXUS_SNAPSHOT_ERR_PARAM;

    u32 i = 0, j = 0, n = 0;
    while (i < from->count || j < to->count) {
        if (n >= max_out) { *out_count = n; return NXUS_SNAPSHOT_ERR_FULL; }

        if (i < from->count && (j >= to->count || from->addresses[i] < to->addresses[j])) {
            out[n].address = from->addresses[i];
            out[n].size = 0;                 /* vanished */
            out[n].reserved = 1;
            n++; i++;
            continue;
        }
        if (j < to->count && (i >= from->count || to->addresses[j] < from->addresses[i])) {
            out[n].address = to->addresses[j];
            out[n].size = 0;                 /* appeared */
            out[n].reserved = 2;
            n++; j++;
            continue;
        }

        if (from->hashes[i] != to->hashes[j]) {
            out[n].address = to->addresses[j];
            out[n].size = to->block_size;
            out[n].reserved = 0;
            n++;
        }
        i++; j++;
    }

    *out_count = n;
    return NXUS_SNAPSHOT_OK;
}
