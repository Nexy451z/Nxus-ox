/* Snapshot service: A/B block-hash snapshots of the target's memory. */
#pragma once

#include <switch.h>

#include "nxus_protocol.h"
#include "nxus_snapshot.h"

Result nxusSnapshotServiceInit(void);

/* Capture into slot A/B.  scope is a NxusScanScope. */
Result nxusSnapshotTake(u32 slot, u32 scope, u64 range_begin, u64 range_end,
                        u32 block_size, NxusSnapshotSummary *out);

/* Compare two slots and cache the changed-block list for paging. */
Result nxusSnapshotCompare(u32 from_slot, u32 to_slot, NxusSnapshotSummary *out);

/* Page the cached changed-block list. */
u32 nxusSnapshotGetChanged(NxusChangedBlockWire *out, u32 max_entries, u32 offset);

void nxusSnapshotGetSummary(u32 slot, NxusSnapshotSummary *out);

/* Drop both captures so the heap they charge can be reused (SnapshotRelease /
   ScanReset).  The next capture reallocates on demand. */
void nxusSnapshotReleaseAll(void);
