#include "nxus_snapshot.h"

#include <string.h>

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

int nxusSnapshotCapture(NxusSnapshot *snapshot, const NxusScanRegion *regions, u32 region_count,
                        NxusReadFn read, void *read_ctx,
                        u8 *chunk, u32 chunk_size,
                        NxusScanStats *stats, int *cancel) {
    if (snapshot == NULL || regions == NULL || read == NULL || chunk == NULL ||
        snapshot->hashes == NULL || snapshot->addresses == NULL || chunk_size < 16) {
        return NXUS_SNAPSHOT_ERR_PARAM;
    }
    if (snapshot->block_size == 0) return NXUS_SNAPSHOT_ERR_PARAM;

    snapshot->count = 0;
    snapshot->region_count = region_count;

    const u32 block_size = snapshot->block_size;
    u64 total_bytes = 0;
    for (u32 r = 0; r < region_count; r++) total_bytes += regions[r].size;

    if (stats != NULL) {
        memset(stats, 0, sizeof(*stats));
        stats->regions_total = region_count;
    }

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
