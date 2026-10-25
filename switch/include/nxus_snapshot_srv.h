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

/* Release both captures and FREE the hash/address arrays (2 x 256 KiB once both
   slots were captured), so the memory really goes back to the 8 MB inner heap
   instead of staying resident while the bookkeeping says otherwise (SnapshotRelease
   / ScanReset).  The next capture re-allocates them through the same on-demand
   path the first capture uses (snapshotSlotEnsure()), so a released session keeps
   working; the slots simply read as "not captured" until then. */
void nxusSnapshotReleaseAll(void);

/* Which slots currently own their hash/address arrays (bit n = slot n), and how
   many bytes that is.  The server charges exactly this against its heap budget, so
   "released" and "resident" cannot differ. */
u32  nxusSnapshotResidentSlots(void);
u64  nxusSnapshotResidentBytes(void);
